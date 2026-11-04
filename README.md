# robertparker

robertparker grades domains. Get it? Like Domaine where wine is made. And he grades them...

It is a small Go library for analyzing domain names: splitting them into their parts, scoring their Shannon entropy, measuring Levenshtein distance between them, and generating lookalike permutations for finding typosquatting and phishing domains.

I wrote it because I did not find a good library that performed these simple functions that: 1. understands internationalized domain names like pure unicode or punycode domains, and 2. understands the difference in control between public TLDs like .com, and their secondary and tertiary levels, and private platforms like appspot.com where control rests in the third level and below.

## Functions

| Function | What it does |
| --- | --- |
| `NewDomain(s string) *Domain` | Splits a domain into its public suffix, registrable label, and subdomains, using the [Public Suffix List](https://publicsuffix.org/). Accepts Unicode or punycode, is case-insensitive, and strips a leading `www.` and a trailing dot. |
| `Entropy(d *Domain) float64` | Shannon entropy of the labels below the public suffix (`Secondary` and `Tertiary`). Stores the result in `d.Entropy` and returns it. Results are identical across platforms. |
| `Permute(d *Domain) []Permutation` | Generates lookalikes of the registrable label. Stores them in `d.Permutations` and returns them. See [Permutations](#permutations). |
| `Levenshtein(s1, s2 string) int` | Edit distance between two strings, counting Unicode characters rather than bytes. |
| `Process(ctx, domains <-chan string, opts Options) <-chan Result` | Analyzes a stream of domains concurrently. See [Processing many domains](#processing-many-domains). |
| `NewLimiter(concurrent int, perSecond float64) *Limiter` | Caps calls to an external service across all workers. See [Network calls](#network-calls). |
| `EmailAnalyzer(resolver Resolver, limiter *Limiter) Analyzer` | Checks a domain's SPF and DMARC records, and adds to `d.Findings`. See [Email checks](#email-checks). |
| `Grade(d *Domain) string` | Works out a letter grade from `d.Findings`. Stores it in `d.Grade` and returns it. See [Grades](#grades). |

### Domain

| Field | Example for `login.d1y6jrbzotnyjg.cloudfront.net` |
| --- | --- |
| `FQDN` | The input, minus a leading `www.`: `login.d1y6jrbzotnyjg.cloudfront.net` |
| `Suffix` | The public suffix, in punycode: `cloudfront.net` |
| `Secondary` | The registrable label directly under the suffix: `d1y6jrbzotnyjg` |
| `Tertiary` | Labels above that: `["login"]` |
| `ICANN` | Whether the suffix is an ICANN TLD (`true` for `com`) or a private platform (`false` for `cloudfront.net`, `appspot.com`) |
| `Entropy` | Set by `Entropy` |
| `Permutations` | Set by `Permute` |
| `Findings` | What the checks found. Left out of JSON if there are none |
| `Grade` | Set by `Grade`. Left out of JSON if there isn't one |

### Permutations

`Permute` only changes the label the owner of a domain controls, the one directly under the public suffix: `google` in `www.google.com`, or `foo` in `bar.foo.appspot.com`. Subdomains are dropped, since the lookalike an attacker registers is the domain itself.

Each `Permutation` has a `Fuzzer`, the permuted `Domain` in Unicode, and its `ASCII` (punycode) form. Every result is valid for registration under IDNA2008, results are deduplicated and exclude the original, and output order is deterministic.

| Fuzzer | Example for `example.com` |
| --- | --- |
| `addition` | `examplea.com` |
| `bitsquatting` | `dxample.com` |
| `homoglyph` | `еxample.com` (Cyrillic е, `xn--xample-2of.com`), `examp1e.com` |
| `hyphenation` | `exam-ple.com` |
| `insertion` | `exsample.com` |
| `omission` | `exmple.com` |
| `repetition` | `exaample.com` |
| `replacement` | `exanple.com` |
| `subdomain` | `exam.ple.com` |
| `transposition` | `exmaple.com` |
| `vowel-swap` | `exomple.com` |
| `tld-swap` | `example.net` (ICANN domains only) |

### Processing many domains

`Process` reads domains from a channel, runs `NewDomain` and a list of `Analyzer`s on each with a pool of workers, and sends a `Result` for each on the channel it returns. Only a few domains per worker are in progress at once, so the input can be any length, and results start arriving before it ends.

An `Analyzer` is `func(ctx context.Context, d *Domain) error`. `EntropyAnalyzer` and `PermuteAnalyzer` wrap `Entropy` and `Permute`. All of a domain's analyzers run even if one fails, and their errors are joined in `Result.Err`.

| `Options` field | Meaning |
| --- | --- |
| `Workers` | Domains analyzed at once. Defaults to `runtime.GOMAXPROCS(0)`, which suits CPU-bound analyzers; network-bound analyzers can use many more. |
| `Analyzers` | Run in order on each domain. |
| `Timeout` | If set, the time allowed for all analyzers on one domain. Its context is cancelled when it runs out. |
| `Unordered` | Send results as they finish, so one slow domain doesn't hold up the rest. By default, results are in input order, which holds back finished results behind a slow one. |
| `Encode` | If set, turns each analyzed domain into `Result.Encoded` on its worker. Use it to serialize results for output, so that serializing runs in parallel and the code reading results only has to write the bytes. |

Cancelling `ctx` stops `Process`: it stops reading input, drops results not yet sent, and closes the results channel once its workers have returned. Code sending domains should also stop when `ctx` is done.

### Network calls

A `Limiter` caps the calls to one external service, such as a DNS resolver or an API, both at once and per second. Share one per service across all workers, so the cap holds however many workers there are. `Do` waits for a slot and the rate limit, and returns `ctx.Err()` without calling the function if the context is done first.

```go
resolver := robertparker.NewLimiter(50, 200) // at most 50 lookups at once, 200 a second

lookup := func(ctx context.Context, d *robertparker.Domain) error {
	return resolver.Do(ctx, func(ctx context.Context) error {
		_, err := net.DefaultResolver.LookupHost(ctx, d.FQDN)
		return err
	})
}

opts := robertparker.Options{
	Workers:   500, // mostly waiting on the network, so far more than the number of CPUs
	Timeout:   5 * time.Second,
	Unordered: true,
	Analyzers: []robertparker.Analyzer{robertparker.EntropyAnalyzer, lookup},
}
for r := range robertparker.Process(ctx, domains, opts) {
	// ...
}
```

### Email checks

`EmailAnalyzer` reads a domain's public DNS records, and adds a `Finding` for each problem, with a check ID, a severity, a message, and the standard it comes from. It checks the registrable domain, since that's where these records are normally published, so `mail.example.com` is checked as `example.com`.

`net.DefaultResolver` works as the `Resolver`. Pass a shared `Limiter` to cap lookups.

| Check | Standard | What it looks for |
| --- | --- | --- |
| `spf-record` | RFC 7208 | Exactly one SPF record |
| `spf-syntax` | RFC 7208 | Valid mechanisms and modifiers |
| `spf-all` | RFC 7208 | Ends in `-all` or `~all`, following redirects |
| `spf-lookups` | RFC 7208 | At most 10 DNS lookups, following includes and redirects |
| `spf-include` | RFC 7208 | Includes and redirects each find one SPF record |
| `spf-ptr` | RFC 7208 | No deprecated `ptr` mechanism |
| `dmarc-record` | RFC 9989 | Exactly one record, found with the DNS tree walk |
| `dmarc-policy` | RFC 9989 | A valid policy of `quarantine` or `reject` |
| `dmarc-subdomain-policy` | RFC 9989 | `sp` and `np` don't weaken it |
| `dmarc-testing` | RFC 9989 | Not in test mode (`t=y`) |
| `dmarc-removed-tag` | RFC 9989 | No `pct`, `rf`, or `ri` tags |
| `dmarc-reporting` | RFC 9989 | A valid `rua` |
| `dmarc-report-authorization` | RFC 9990 | External report destinations authorize the reports |

A lookup that fails, such as a timeout, is reported as a `SeverityUnknown` finding and an error, never as a missing record, so a network problem can't make a domain look misconfigured.

### Grades

`Grade` starts at 100, and takes off 15 for each warning and 40 for each failure. Information findings cost nothing. 90 or more is an A, 80 a B, 70 a C, 60 a D, and anything lower an F.

A domain gets no grade if any check couldn't finish, since a grade that ignored it would be a guess, or if it has no registrable domain, like `com`. Run `GradeAnalyzer` after the analyzers that add findings.

## Usage

Requires Go 1.27.3 or later. With Go 1.21 or later, the right toolchain is downloaded automatically.

```
go get github.com/mikecb/robertparker
```

```go
package main

import (
	"encoding/json"
	"fmt"

	"github.com/mikecb/robertparker"
)

func main() {
	d := robertparker.NewDomain("login.d1y6jrbzotnyjg.cloudfront.net")
	robertparker.Entropy(d)
	out, _ := json.MarshalIndent(d, "", "  ")
	fmt.Println(string(out))

	for _, p := range robertparker.Permute(robertparker.NewDomain("www.example.com")) {
		fmt.Println(p.Fuzzer, p.Domain, p.ASCII)
	}

	fmt.Println(robertparker.Levenshtein("δοκιμή.com", "δοκιμ.com"))
}
```

Output:

```
{
  "FQDN": "login.d1y6jrbzotnyjg.cloudfront.net",
  "Suffix": "cloudfront.net",
  "Secondary": "d1y6jrbzotnyjg",
  "Tertiary": [
    "login"
  ],
  "ICANN": false,
  "Entropy": 3.7216117239699007,
  "Permutations": null
}
addition examplea.com examplea.com
addition exampleb.com exampleb.com
addition examplec.com examplec.com
...
homoglyph еxample.com xn--xample-2of.com
...
tld-swap example.site example.site
1
```

`www.example.com` produces 210 permutations.

## Command line

```
go install github.com/mikecb/robertparker/cmd/robertparker@latest
```

`robertparker` reads domains from its arguments, from a file with `-f`, or from stdin, one per line, ignoring blank lines and `#` comments. Input is streamed through `Process`, so lists can be any size. By default it prints each domain as one JSON object per line, in input order, for piping into tools like `jq`.

```
$ robertparker www.google.com
{"FQDN":"google.com","Suffix":"com","Secondary":"google","ICANN":true,"Entropy":1.9182958340544896,"Permutations":null}

$ robertparker -o text www.google.com login.d1y6jrbzotnyjg.cloudfront.net δοκιμή.δοκιμή
DOMAIN                               SUFFIX          SECONDARY       SUBDOMAINS  ICANN  ENTROPY
google.com                           com             google          -           true   1.918
login.d1y6jrbzotnyjg.cloudfront.net  cloudfront.net  d1y6jrbzotnyjg  login       false  3.722
δοκιμή.δοκιμή                        xn--jxalpdlp    xn--jxalpdlp    -           false  2.918

$ robertparker -o text -permute example.com
DOMAIN       FUZZER         PERMUTATION     ASCII
example.com  addition       examplea.com    examplea.com
...
example.com  homoglyph      еxample.com     xn--xample-2of.com
...

$ robertparker -permute -f domains.txt > permutations.jsonl

$ robertparker -checks email -o text example.com nonexistent-domain-xyz-12345.com
DOMAIN                            GRADE  SEVERITY  CHECK            MESSAGE
example.com                       B      warning   dmarc-reporting  No valid rua, so there are no reports on who sends mail as this domain.
nonexistent-domain-xyz-12345.com  F      failure   spf-record       No SPF record, so anyone can claim to send mail from this domain.
nonexistent-domain-xyz-12345.com  F      failure   dmarc-record     No DMARC record, so receivers have no policy for mail that fails authentication.
```

| Flag | Meaning |
| --- | --- |
| `-f file` | Read domains from `file`, one per line, after any given as arguments. `-` reads stdin. |
| `-permute` | Also generate lookalike permutations of each domain. |
| `-checks list` | Comma-separated checks to run and grade. `email` is the only one so far. Off by default, since it makes DNS lookups. |
| `-o format` | `json` (default, one object per line), `pretty` (indented JSON), or `text` (aligned columns, one row per domain, or per permutation with `-permute`, or per finding with `-checks`). Text can't show `-permute` and `-checks` together. Text is aligned in blocks of 1000 rows, so memory stays bounded on large inputs. |
| `-workers number` | Domains to analyze at once. Defaults to the number of CPUs, or 64 with `-checks`, which mostly wait on the network. |
| `-unordered` | Print results as they finish, instead of in input order. |
| `-timeout time` | Time allowed for the checks on one domain. Defaults to 10s. |
| `-rate number` | DNS lookups per second, or 0 for no limit. Defaults to 100. |
| `-resolver host` | DNS server to use instead of the system's, as `host` or `host:port`. Home routers often can't handle the large responses of big domains, which then show as `unknown`. |

The tool runs with a garbage collection target of 400 instead of Go's default of 100, which is about 40% faster with `-permute` for around 25 MB more memory. Set the `GOGC` environment variable to override it.

It exits with 1 if it can't read its input or an analysis fails, 2 for invalid flags, and 130 if interrupted with Ctrl-C, after printing the results it has.

## Building and testing

```
git clone https://github.com/mikecb/robertparker
cd robertparker
go build ./...
go vet ./...
go test ./...
```

`go run ./cmd/robertparker [flags] [domain ...]` runs the command line tool from source.

GitHub Actions runs the build, vet, and tests (with the race detector) on amd64 and arm64 for every push and pull request to `master`, and both must pass before a pull request can merge.

## Roadmap

Future plans are tracked in [TODO.md](TODO.md).

## License

MIT. See [license.md](license.md).
