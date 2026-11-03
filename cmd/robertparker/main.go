// Command robertparker grades domains from the command line.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/mikecb/robertparker"
)

const usage = `Usage: robertparker [flags] [domain ...]

Splits each domain into its public suffix, registrable label, and subdomains,
and scores its Shannon entropy. With -permute, also generates lookalike
permutations of each domain, for finding typosquatting and phishing domains.

Domains are read from the arguments, then from -f, or from stdin if neither is
given, one per line. Blank lines and lines starting with # are ignored.

Flags:
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is main, with its inputs and outputs passed in so it can be tested. It returns the exit code.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("robertparker", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}
	file := fs.String("f", "", "read domains from `file`, one per line (- for stdin)")
	permute := fs.Bool("permute", false, "generate lookalike permutations of each domain")
	format := fs.String("o", "json", "output `format`: json (one object per line), pretty (indented JSON), or text (aligned columns)")
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

	domains := fs.Args()
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
	case len(domains) == 0:
		if isTerminal(stdin) {
			fs.Usage()
			return 2
		}
		in = stdin
	}
	if in != nil {
		lines, err := readDomains(in)
		if err != nil {
			fmt.Fprintf(stderr, "robertparker: %v\n", err)
			return 1
		}
		domains = append(domains, lines...)
	}

	var enc *json.Encoder
	var tw *tabwriter.Writer
	switch *format {
	case "json":
		enc = json.NewEncoder(stdout)
	case "pretty":
		enc = json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
	case "text":
		tw = tabwriter.NewWriter(stdout, 0, 8, 2, ' ', 0)
		if *permute {
			fmt.Fprintln(tw, "DOMAIN\tFUZZER\tPERMUTATION\tASCII")
		} else {
			fmt.Fprintln(tw, "DOMAIN\tSUFFIX\tSECONDARY\tSUBDOMAINS\tICANN\tENTROPY")
		}
	}

	for _, s := range domains {
		d := robertparker.NewDomain(s)
		robertparker.Entropy(d)
		if *permute {
			robertparker.Permute(d)
		}
		if enc != nil {
			if err := enc.Encode(d); err != nil {
				fmt.Fprintf(stderr, "robertparker: %v\n", err)
				return 1
			}
		} else {
			writeText(tw, d, *permute)
		}
	}
	if tw != nil {
		if err := tw.Flush(); err != nil {
			fmt.Fprintf(stderr, "robertparker: %v\n", err)
			return 1
		}
	}
	return 0
}

// readDomains reads one domain per line, skipping blank lines and # comments.
func readDomains(r io.Reader) ([]string, error) {
	var domains []string
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}
	return domains, s.Err()
}

// writeText writes a domain as a row of columns, or one row per permutation.
func writeText(w io.Writer, d *robertparker.Domain, permute bool) {
	if permute {
		for _, p := range d.Permutations {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", d.FQDN, p.Fuzzer, p.Domain, p.ASCII)
		}
		return
	}
	entropy := d.Entropy
	if entropy == 0 {
		entropy = 0 // Drop the sign from -0.
	}
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%t\t%.3f\n", d.FQDN, d.Suffix, orDash(d.Secondary), orDash(strings.Join(d.Tertiary, ".")), d.ICANN, entropy)
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
