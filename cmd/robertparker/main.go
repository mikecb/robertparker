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
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/mikecb/robertparker"
)

const usage = `Usage: robertparker [flags] [domain ...]

Splits each domain into its public suffix, registrable label, and subdomains,
and scores its Shannon entropy. With -permute, also generates lookalike
permutations of each domain, for finding typosquatting and phishing domains.
With -checks, also checks each domain's public configuration and grades it.

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

	// networkWorkers is the default for -workers with -checks, which mostly wait on the network rather than use CPU.
	networkWorkers = 64

	// lookupWorkers is the default for -workers with -lookup. Each domain already looks up many names at once.
	lookupWorkers = 8

	// lookupTimeout is the default for -timeout with -lookup. A domain has hundreds of lookups, and spends most of its
	// time waiting behind -rate, so this only catches something stuck. Each lookup has its own short timeout.
	lookupTimeout = 10 * time.Minute
)

// resolver does the DNS lookups for -checks, lookalikes those for -lookup, and registrations the lookups for
// -registration. Tests replace them.
var (
	resolver      robertparker.Resolver           = net.DefaultResolver
	lookalikes    robertparker.LookalikeResolver  = net.DefaultResolver
	registrations robertparker.RegistrationSource = &robertparker.RDAP{}
)

// textView is what -o text shows: a header, and the rows for a domain.
type textView struct {
	header string
	rows   func(io.Writer, *robertparker.Domain)
}

var (
	domainView      = textView{"DOMAIN\tSUFFIX\tSECONDARY\tSUBDOMAINS\tICANN\tENTROPY", writeDomain}
	permutationView = textView{"DOMAIN\tFUZZER\tPERMUTATION\tASCII", writePermutations}
	findingView     = textView{"DOMAIN\tGRADE\tAREAS\tSEVERITY\tCHECK\tMESSAGE", writeFindings}
	lookalikeView   = textView{"DOMAIN\tFUZZER\tLOOKALIKE\tASCII\tMAIL\tSHARED-NS\tBROKEN-DNS\tADDRESSES", writeLookalikes}

	registrationView = textView{"DOMAIN\tSUSPICION\tLOOKALIKE\tASCII\tREGISTRAR\tREGISTERED\tREASONS", writeRegistrations}
)

// webDial makes the connections for -checks tls and web, if set. Tests replace it.
var webDial func(ctx context.Context, network, addr string) (net.Conn, error)

func main() {
	tuneGC()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// newResolver returns a resolver that asks the DNS server at addr, on port 53 unless addr has its own. Home routers
// often can't handle the large TCP responses that big domains need, which is one reason to choose a server.
func newResolver(addr string) *net.Resolver {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}}
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
	lookup := fs.Bool("lookup", false, "find which permutations of each domain exist, using DNS only")
	registration := fs.Bool("registration", false, "compare each lookalike's registration with the original's, and rank them (implies -lookup)")
	suspicious := fs.Bool("suspicious", false, "only show lookalikes ranked medium or high (implies -registration)")
	format := fs.String("o", "json", "output `format`: json (one object per line), pretty (indented JSON), or text (aligned columns)")
	workers := fs.Int("workers", runtime.GOMAXPROCS(0), "`number` of domains to analyze at once")
	unordered := fs.Bool("unordered", false, "print results as they finish, instead of in input order")
	checks := fs.String("checks", "", "comma-separated `list` of checks to run: email, tls, web. These make DNS lookups and web requests")
	timeout := fs.Duration("timeout", 10*time.Second, "`time` allowed for the checks on one domain")
	rate := fs.Float64("rate", 100, "DNS lookups and web requests per `second`, or 0 for no limit")
	dnsServer := fs.String("resolver", "", "DNS server to use, as `host` or host:port, instead of the system's")
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
	email, web := false, robertparker.WebConfig{DialContext: webDial}
	if *checks != "" {
		for _, c := range strings.Split(*checks, ",") {
			switch c {
			case robertparker.AreaEmail:
				email = true
			case robertparker.AreaTLS:
				web.TLS = true
			case robertparker.AreaWeb:
				web.Web = true
			default:
				fmt.Fprintf(stderr, "robertparker: unknown check %q\n", c)
				return 2
			}
		}
	}
	*registration = *registration || *suspicious
	*lookup = *lookup || *registration
	checking := email || web.TLS || web.Web
	if checking && (*permute || *lookup) && *format == "text" {
		fmt.Fprintln(stderr, "robertparker: -o text can show -permute, -lookup, or -checks, not both")
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
	view := domainView
	if *permute {
		opts.Analyzers = append(opts.Analyzers, robertparker.PermuteAnalyzer)
		view = permutationView
	}
	if checking || *lookup {
		set := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
		dns, names, source := resolver, lookalikes, registrations
		if *dnsServer != "" {
			custom := newResolver(*dnsServer)
			dns, names = custom, custom
			if _, real := source.(*robertparker.RDAP); real {
				dial := (&net.Dialer{Resolver: custom}).DialContext
				source = &robertparker.RDAP{Client: &http.Client{Transport: &http.Transport{DialContext: dial}}}
			}
			if web.DialContext == nil {
				web.DialContext = (&net.Dialer{Resolver: custom}).DialContext
			}
		}
		limiter := robertparker.NewLimiter(networkWorkers, *rate)
		if email {
			opts.Analyzers = append(opts.Analyzers, robertparker.EmailAnalyzer(dns, limiter))
		}
		if web.TLS || web.Web {
			opts.Analyzers = append(opts.Analyzers, robertparker.WebAnalyzer(web, limiter))
		}
		if checking {
			opts.Analyzers = append(opts.Analyzers, robertparker.GradeAnalyzer)
			view = findingView
			if !set["workers"] {
				opts.Workers = networkWorkers
			}
		}
		opts.Timeout = *timeout
		if *lookup {
			opts.Analyzers = append(opts.Analyzers, robertparker.LookalikeAnalyzer(names, limiter))
			view = lookalikeView
			if *registration {
				opts.Analyzers = append(opts.Analyzers, robertparker.RegistrationAnalyzer(source, nil))
				view = registrationView
			}
			if *suspicious {
				opts.Analyzers = append(opts.Analyzers, onlySuspicious)
			}
			if !set["workers"] {
				opts.Workers = lookupWorkers
			}
			if !set["timeout"] {
				opts.Timeout = lookupTimeout
			}
		}
	}
	opts.Encode = encoder(*format, view)

	w := bufio.NewWriter(stdout)
	var out io.Writer = w
	var tw *tabwriter.Writer
	if *format == "text" {
		tw = tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
		out = tw
		fmt.Fprintln(tw, view.header)
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
func encoder(format string, view textView) func(*robertparker.Domain) ([]byte, error) {
	buffers := sync.Pool{New: func() any { return new(bytes.Buffer) }}
	return func(d *robertparker.Domain) ([]byte, error) {
		b := buffers.Get().(*bytes.Buffer)
		defer buffers.Put(b)
		b.Reset()
		if format == "text" {
			view.rows(b, d)
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

// writeDomain writes a domain as a row of columns.
func writeDomain(w io.Writer, d *robertparker.Domain) {
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%t\t%.3f\n", d.FQDN, d.Suffix, orDash(d.Secondary), orDash(strings.Join(d.Tertiary, ".")), d.ICANN, d.Entropy)
}

// writePermutations writes one row per permutation of a domain.
func writePermutations(w io.Writer, d *robertparker.Domain) {
	for _, p := range d.Permutations {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", d.FQDN, p.Fuzzer, p.Domain, p.ASCII)
	}
}

// writeFindings writes one row per finding on a domain, or a single row with its grades if there are none.
func writeFindings(w io.Writer, d *robertparker.Domain) {
	areas := make([]string, 0, len(d.Grades))
	for area, grade := range d.Grades {
		areas = append(areas, area+"="+grade)
	}
	sort.Strings(areas)
	grades := orDash(strings.Join(areas, ","))
	for _, f := range d.Findings {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", d.FQDN, orDash(d.Grade), grades, f.Severity, f.Check, f.Message)
	}
	if len(d.Findings) == 0 {
		fmt.Fprintf(w, "%s\t%s\t%s\t-\t-\t-\n", d.FQDN, orDash(d.Grade), grades)
	}
}

// writeLookalikes writes one row per lookalike that exists.
func writeLookalikes(w io.Writer, d *robertparker.Domain) {
	yes := func(b bool) string {
		if b {
			return "yes"
		}
		return "-"
	}
	for _, l := range d.Lookalikes {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", d.FQDN, l.Fuzzer, l.Domain, l.ASCII, yes(len(l.MailServers) > 0), yes(l.SharedNameServers), yes(l.BrokenDNS), orDash(strings.Join(l.Addresses, ",")))
	}
}

// writeRegistrations writes one row per lookalike, with what makes it suspicious.
func writeRegistrations(w io.Writer, d *robertparker.Domain) {
	for _, l := range d.Lookalikes {
		registered := ""
		if !l.Registered.IsZero() {
			registered = l.Registered.Format(time.DateOnly)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", d.FQDN, l.Suspicion, l.Domain, l.ASCII, orDash(l.Registrar), orDash(registered), orDash(strings.Join(l.Reasons, ", ")))
	}
}

// onlySuspicious is an Analyzer that keeps the lookalikes ranked medium or high.
func onlySuspicious(_ context.Context, d *robertparker.Domain) error {
	d.Lookalikes = slices.DeleteFunc(d.Lookalikes, func(l robertparker.Lookalike) bool {
		return l.Suspicion != robertparker.SuspicionHigh && l.Suspicion != robertparker.SuspicionMedium
	})
	return nil
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
