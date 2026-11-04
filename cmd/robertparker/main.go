// Command robertparker grades domains from the command line.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/mikecb/robertparker"
)

const usage = `Usage: robertparker [flags] [domain ...]

Splits each domain into its public suffix, registrable label, and subdomains,
and scores its Shannon entropy. With -permute, also generates lookalike
permutations of each domain, for finding typosquatting and phishing domains.

Domains are read from the arguments, then from -f, or from stdin if neither is
given, one per line. Blank lines and lines starting with # are ignored. Input
is streamed, so it can be any length.

Flags:
`

const (
	// textBlock is how many rows of text output are aligned and written at a time, so memory stays bounded.
	textBlock = 1000

	// gcPercent trades a little memory for less garbage collection. Measured on 20,000 domains with -permute, it is
	// about 40% faster than Go's default of 100, using about 50 MB instead of about 25 MB. The live heap is small and
	// bounded by streaming, so this doesn't grow with the input. 800 and 1600 used far more memory for no real gain.
	gcPercent = 400
)

func main() {
	tuneGC()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// tuneGC sets the garbage collection target, unless the GOGC environment variable already chose one.
func tuneGC() {
	if _, ok := os.LookupEnv("GOGC"); !ok {
		debug.SetGCPercent(gcPercent)
	}
}

// run is main, with its inputs and outputs passed in so it can be tested. It returns the exit code.
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("robertparker", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}
	file := fs.String("f", "", "read domains from `file`, one per line (- for stdin)")
	permute := fs.Bool("permute", false, "generate lookalike permutations of each domain")
	format := fs.String("o", "json", "output `format`: json (one object per line), pretty (indented JSON), or text (aligned columns)")
	workers := fs.Int("workers", runtime.GOMAXPROCS(0), "`number` of domains to analyze at once")
	unordered := fs.Bool("unordered", false, "print results as they finish, instead of in input order")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *format != "json" && *format != "pretty" && *format != "text" {
		fmt.Fprintf(stderr, "robertparker: unknown output format %q\n", *format)
		return 2
	}
	if *workers < 1 {
		fmt.Fprintf(stderr, "robertparker: -workers must be at least 1\n")
		return 2
	}

	var in io.Reader
	switch {
	case *file == "-":
		in = stdin
	case *file != "":
		f, err := os.Open(*file)
		if err != nil {
			fmt.Fprintf(stderr, "robertparker: %v\n", err)
			return 1
		}
		defer f.Close()
		in = f
	case fs.NArg() == 0:
		if isTerminal(stdin) {
			fs.Usage()
			return 2
		}
		in = stdin
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	domains, readErr := readDomains(ctx, fs.Args(), in)

	opts := robertparker.Options{
		Workers:   *workers,
		Unordered: *unordered,
		Analyzers: []robertparker.Analyzer{robertparker.EntropyAnalyzer},
		Encode:    encoder(*format, *permute),
	}
	if *permute {
		opts.Analyzers = append(opts.Analyzers, robertparker.PermuteAnalyzer)
	}

	w := bufio.NewWriter(stdout)
	var out io.Writer = w
	var tw *tabwriter.Writer
	if *format == "text" {
		tw = tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
		out = tw
		if *permute {
			fmt.Fprintln(tw, "DOMAIN\tFUZZER\tPERMUTATION\tASCII")
		} else {
			fmt.Fprintln(tw, "DOMAIN\tSUFFIX\tSECONDARY\tSUBDOMAINS\tICANN\tENTROPY")
		}
	}

	code, rows := 0, 0
	for r := range robertparker.Process(ctx, domains, opts) {
		if r.Err != nil {
			fmt.Fprintf(stderr, "robertparker: %s: %v\n", r.Input, r.Err)
			code = 1
		}
		_, err := out.Write(r.Encoded)
		if err == nil && tw != nil {
			rows += bytes.Count(r.Encoded, []byte{'\n'})
			if rows >= textBlock {
				err = tw.Flush()
				rows = 0
			}
		}
		if err != nil {
			fmt.Fprintf(stderr, "robertparker: %v\n", err)
			return 1
		}
	}
	if tw != nil {
		if err := tw.Flush(); err != nil {
			fmt.Fprintf(stderr, "robertparker: %v\n", err)
			return 1
		}
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintf(stderr, "robertparker: %v\n", err)
		return 1
	}

	if ctx.Err() != nil {
		fmt.Fprintln(stderr, "robertparker: interrupted")
		return 130
	}
	if err := <-readErr; err != nil {
		fmt.Fprintf(stderr, "robertparker: %v\n", err)
		return 1
	}
	return code
}

// readDomains sends args, then one domain per line of in, skipping blank lines and # comments. It stops early if
// ctx is done. Once it has finished reading, it sends any read error on the second channel, then closes the first.
func readDomains(ctx context.Context, args []string, in io.Reader) (<-chan string, <-chan error) {
	domains := make(chan string)
	errc := make(chan error, 1)
	go func() {
		defer close(domains)
		send := func(d string) bool {
			select {
			case domains <- d:
				return true
			case <-ctx.Done():
				return false
			}
		}
		for _, d := range args {
			if !send(d) {
				return
			}
		}
		if in == nil {
			errc <- nil
			return
		}
		s := bufio.NewScanner(in)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line != "" && !strings.HasPrefix(line, "#") && !send(line) {
				return
			}
		}
		errc <- s.Err()
	}()
	return domains, errc
}

// encoder returns the function that turns a domain into its output bytes, which Process runs on its workers.
func encoder(format string, permute bool) func(*robertparker.Domain) ([]byte, error) {
	buffers := sync.Pool{New: func() any { return new(bytes.Buffer) }}
	return func(d *robertparker.Domain) ([]byte, error) {
		b := buffers.Get().(*bytes.Buffer)
		defer buffers.Put(b)
		b.Reset()
		if format == "text" {
			writeText(b, d, permute)
		} else {
			enc := json.NewEncoder(b)
			if format == "pretty" {
				enc.SetIndent("", "  ")
			}
			if err := enc.Encode(d); err != nil {
				return nil, err
			}
		}
		return bytes.Clone(b.Bytes()), nil
	}
}

// writeText writes a domain as a row of columns, or one row per permutation.
func writeText(w io.Writer, d *robertparker.Domain, permute bool) {
	if permute {
		for _, p := range d.Permutations {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", d.FQDN, p.Fuzzer, p.Domain, p.ASCII)
		}
		return
	}
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%t\t%.3f\n", d.FQDN, d.Suffix, orDash(d.Secondary), orDash(strings.Join(d.Tertiary, ".")), d.ICANN, d.Entropy)
}

// orDash returns s, or "-" if it is empty, so text columns are never blank.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// isTerminal reports whether r is an interactive terminal, where waiting for input on stdin would look like a hang.
func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
