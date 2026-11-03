// Command robertparker grades domains from the command line.
package main

import (
	"bufio"
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

	// gcPercent trades a little memory for less garbage collection, which is the main cost of -permute. Measured on
	// 20,000 domains, it is about a third faster than Go's default of 100, using 50-70 MB instead of about 20 MB. The live
	// heap is small and bounded by streaming, so this doesn't grow with the input. Higher values gained nothing.
	gcPercent = 800
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
	}
	if *permute {
		opts.Analyzers = append(opts.Analyzers, robertparker.PermuteAnalyzer)
	}

	w := bufio.NewWriter(stdout)
	var enc *json.Encoder
	var tw *tabwriter.Writer
	switch *format {
	case "json":
		enc = json.NewEncoder(w)
	case "pretty":
		enc = json.NewEncoder(w)
		enc.SetIndent("", "  ")
	case "text":
		tw = tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
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
		var err error
		if enc != nil {
			err = enc.Encode(r.Domain)
		} else {
			rows += writeText(tw, r.Domain, *permute)
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

// writeText writes a domain as a row of columns, or one row per permutation, and returns the number of rows.
func writeText(w io.Writer, d *robertparker.Domain, permute bool) int {
	if permute {
		for _, p := range d.Permutations {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", d.FQDN, p.Fuzzer, p.Domain, p.ASCII)
		}
		return len(d.Permutations)
	}
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%t\t%.3f\n", d.FQDN, d.Suffix, orDash(d.Secondary), orDash(strings.Join(d.Tertiary, ".")), d.ICANN, d.Entropy)
	return 1
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
