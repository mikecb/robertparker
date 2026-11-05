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
| `EmailAnalyzer(resolver Resolver, client *http.Client, limiter *Limiter) Analyzer` | Checks a domain's mail servers and email authentication, and adds to `d.Findings`. See [Email checks](#email-checks). |
| `WebAnalyzer(config WebConfig, limiter *Limiter) Analyzer` | Requests a domain's site, and adds to `d.Findings` about its TLS setup and HTTP headers. See [TLS and Web checks](#tls-and-web-checks). |
| `LookalikeAnalyzer(resolver LookalikeResolver, limiter *Limiter) Analyzer` | Finds which permutations of a domain exist, and stores them in `d.Lookalikes`. See [Lookalike lookup](#lookalike-lookup). |
| `RegistrationAnalyzer(source RegistrationSource, now func() time.Time) Analyzer` | Compares each lookalike's registration with the domain's, and ranks them. See [Ranking lookalikes](#ranking-lookalikes). |
| `Grade(d *Domain) string` | Works out letter grades from `d.Findings`. Stores them in `d.Grades` and `d.Grade`, and returns the overall one. See [Grades](#grades). |

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
| `Lookalikes` | The permutations that exist, set by `LookalikeAnalyzer`. Left out of JSON if there are none |
| `LookupFailures` | How many permutations couldn't be looked up, so `Lookalikes` may be missing some |
| `RegistrationFailures` | How many `Lookalikes` couldn't be compared, so they have no `Suspicion` to go on |
| `Grades` | The letter grade for each area checked, set by `Grade`. Left out of JSON if there are none |
| `Grade` | The overall letter grade, set by `Grade`. Left out of JSON if there isn't one |

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

`EmailAnalyzer` reads a domain's public DNS records, plus an MTA-STS policy if it has one, and adds a `Finding` for each problem, with a check ID, a severity, a message, and the standard it comes from. It never connects to a mail server. It checks the registrable domain, since that's where these records are normally published, so `mail.example.com` is checked as `example.com`.

`net.DefaultResolver` works as the `Resolver`. The `client` fetches MTA-STS policies, and can be nil. Pass a shared `Limiter` to cap lookups.

Newer protections that are simply missing, like MTA-STS and TLS-RPT, are only information. What costs a domain is one that's present but broken, since that's what stops mail being delivered.

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
| `mx-record` | RFC 5321 | Can be read, and only reports a failed lookup |
| `mx-resolve` | RFC 5321 | Each mail server resolves |
| `mx-null` | RFC 7505 | A null MX isn't mixed with real mail servers |
| `mx-reverse-dns` | RFC 5321 | Forward-confirmed reverse DNS, as information |
| `parked-spf`, `parked-dmarc` | RFC 7208, RFC 9989 | A parked domain has SPF of `-all` and a DMARC policy of `reject` |
| `parked-null-mx` | RFC 7505 | A parked domain has a null MX, as information |
| `mta-sts` | RFC 8461 | A record leads to a policy that can be fetched, and is in `enforce` mode. None at all is information |
| `mta-sts-mx` | RFC 8461 | The policy covers every mail server |
| `tls-rpt` | RFC 8460 | One valid record. None at all is information |
| `dkim-key` | RFC 6376, RFC 8301 | Keys at common selectors can be read and are at least 2048 bits. Finding none is information, since selectors can't be listed |
| `dkim-hash` | RFC 8301 | Keys allow SHA-256 |
| `dkim-testing` | RFC 6376 | Keys in test mode, as information |

A parked domain is one that takes no mail and whose SPF record authorizes no senders. A domain with no mail servers that does send mail isn't parked. Parked domains that use a parking service's MX records aren't recognised.

A lookup that fails, such as a timeout, is reported as a `SeverityUnknown` finding and an error, never as a missing record, so a network problem can't make a domain look misconfigured. Lookups for checks that are only information don't count, so they can't stop a domain being graded.

DNSSEC and DANE aren't checked yet. When they are, they'll be reported but won't earn a better grade, given their reliability problems.

### TLS and Web checks

`WebAnalyzer` makes ordinary requests to a site, like a browser would, and doesn't probe for anything. It checks the host as given, since each host is its own site, and a registrable domain that isn't reachable gets a second try at `www`. Set `TLS` and `Web` in its `WebConfig` to choose the areas. Both come from the same requests.

| Check | What it looks for |
| --- | --- |
| `tls-https` | The site serves HTTPS |
| `tls-handshake` | The TLS connection works |
| `tls-version` | TLS 1.2 or later, noting TLS 1.2 as information |
| `tls-cipher` | A forward-secret AEAD cipher |
| `tls-post-quantum` | X25519MLKEM768 key exchange, as information |
| `tls-expiry` | Not expired, or expiring within the last tenth of its lifetime |
| `tls-hostname` | The certificate is valid for the host |
| `tls-chain` | The certificate chains to a trusted root |
| `tls-lifetime` | Within the CA/Browser Forum limit for its issue date, for trusted certificates |
| `tls-key` | RSA of at least 2048 bits, or ECDSA of at least 256 |
| `tls-signature` | No SHA-1 or MD5 signature |
| `tls-transparency` | Has Certificate Transparency timestamps, for trusted certificates |
| `web-https` | The site serves HTTPS |
| `web-https-redirect` | HTTP leads to HTTPS, and HTTPS doesn't lead back to HTTP |
| `web-hsts` | `Strict-Transport-Security` for at least a year, noting subdomains and preloading as information |
| `web-csp` | An enforced `Content-Security-Policy`, without `unsafe-inline`, `unsafe-eval`, or wildcards in `default-src` or `script-src` |
| `web-framing` | CSP `frame-ancestors` or `X-Frame-Options` |
| `web-nosniff` | `X-Content-Type-Options: nosniff` |
| `web-referrer` | `Referrer-Policy` doesn't send full URLs to other sites |
| `web-cookies` | Cookies are `Secure`, noting `HttpOnly` and `SameSite` as information |
| `web-cors` | Credentialed responses don't allow other origins |
| `web-permissions`, `web-coop` | `Permissions-Policy` and `Cross-Origin-Opener-Policy`, as information |
| `web-obsolete`, `web-disclosure` | Obsolete headers, and versions given away, as information |
| `web-security-txt` | A `security.txt` that hasn't expired, with a missing one as information |

To be able to report a broken certificate, it connects without verifying, then does the verification itself, so each problem gets its own finding. Nothing sensitive is ever sent.

A normal connection only shows the best a server offers, so a site that also allows old TLS versions or weak ciphers won't show here. The results are what a plain client gets, and a site can treat browsers differently. HSTS preloading isn't looked up, so a preloaded site that doesn't also send the header is reported as not having it.

### Lookalike lookup

`LookalikeAnalyzer` looks up each permutation of a domain, and keeps the ones that exist. It uses DNS only, and never connects to them: they may be malicious, and a request would tell their owner that someone is looking. `net.DefaultResolver` works as the `LookalikeResolver`.

| `Lookalike` field | Meaning |
| --- | --- |
| `Fuzzer`, `Domain`, `ASCII` | The permutation, as in `Permutation` |
| `Addresses`, `NameServers` | What it resolves to |
| `MailServers` | Its mail servers. A null MX doesn't count |
| `SharedNameServers` | It uses the same exact name servers as the original, so it probably has the same owner. Being with the same provider doesn't count, since Cloudflare and others host millions of unrelated domains |
| `BrokenDNS` | It's registered, but its name servers don't answer properly, so there's nothing else to report |

A few things decide what counts as existing:

- A name with no DNS records gets NXDOMAIN. A server failure means the name is delegated to servers that don't work, so it's registered, and is reported with `BrokenDNS`. To be sure it isn't the resolver failing, a random name is tested first.
- Some suffixes answer for every name, which would make anything under them look registered. Each suffix is tested with a random name, and answers that match it don't count. This can miss a wildcard that gives different addresses each time.
- Lookups that time out, even after retries, aren't guessed at. They're counted in `d.LookupFailures` and returned as an error, so a short list can be told apart from a clean one. Some of these are lookalikes with name servers too broken to even fail quickly.

Each query has its own 5 second timeout, which starts after the limiter, since a domain has hundreds of queries and time spent waiting behind a rate limit doesn't mean anything is wrong.

Only registered names are found, so expect a lot for a well-known brand: much of what's found will be defensive registrations and parking pages. `Lookalikes` shows what exists, not what's malicious, and doesn't affect grades.

### Ranking lookalikes

`RegistrationAnalyzer` goes after `LookalikeAnalyzer`. It looks up the registration of the domain and of each lookalike, compares them, and sorts `d.Lookalikes` with the most suspicious first. Each lookalike gets its `Registrar`, `Registered` date, `SameRegistrar`, and a `Suspicion` with the `Reasons` for it.

Each sign counts for points, so that no one thing decides:

| Sign | Points |
| --- | --- |
| Registered in the last year | 2 |
| Different registrar from the original | 1 |
| Can receive mail | 1 |

3 or more is `high`, 2 is `medium`, and less is `low`. A recent registration counts most, because phishing domains tend to be used soon after they're registered. Mail servers count less than they sound like they should, because parking services give their domains them too. The same registrar doesn't clear a lookalike, because brands often use the same big registrars as everyone else, but sharing the same exact name servers does, making it `low` whatever else is true.

`unknown` means there's nothing to compare, which says nothing either way. That's a registry with no RDAP server, a name under a private suffix like `appspot.com`, or a lookup that failed. Failures are counted in `d.RegistrationFailures` and returned as an error.

`Suspicion` is a way to sort lookalikes, and doesn't prove anything. The points are judgement, tuned by looking at 20 well-known domains, where about a tenth of lookalikes came out `high`. An old domain taken over or re-registered can look innocent or suspicious, and a recent one may be harmless.

Registrations come from a `RegistrationSource`. `RDAP` is one, which asks each registry's server using IANA's list, at up to 10 requests a second per server, and waits when a server says it's getting too many. Registries that aren't on that list have no data, which at the time of writing includes `.io`, `.co`, `.de`, and `.us`.

### Grades

Each area that was checked gets its own grade in `d.Grades`, and `d.Grade` is the worst of them, because a strong area doesn't make up for a weak one: good email settings don't help if the certificate has expired.

An area starts at 100, and loses 40 for a failure and 15 for a warning, or 10 for a warning in `web`, which has many more checks and more of them about hardening. Each check costs once, at its worst, however many ways it found a problem. Information findings cost nothing. 90 or more is an A, 80 a B, 70 a C, 60 a D, and anything lower an F.

An area that doesn't apply, like `web` on a domain with no web server, gets no grade, rather than credit for having nothing wrong. An area where a check couldn't finish gets no grade either, since it would be a guess, and then there's no overall grade. Run `GradeAnalyzer` after the analyzers that add findings.

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

$ robertparker -lookup -o text github.com
DOMAIN      FUZZER    LOOKALIKE    ASCII        MAIL  SHARED-NS  BROKEN-DNS  ADDRESSES
github.com  addition  githubb.com  githubb.com  yes   -          -           -
...

$ robertparker -suspicious -o text paypal.com
DOMAIN      SUSPICION  LOOKALIKE   ASCII       REGISTRAR        REGISTERED  REASONS
paypal.com  high       paypcl.com  paypcl.com  NameCheap, Inc.  2026-04-10  has a different registrar from the original, was registered in the last year...
...

$ robertparker -checks email,tls,web -o text mozilla.org
DOMAIN       GRADE  AREAS                SEVERITY  CHECK              MESSAGE
mozilla.org  B      email=A,tls=A,web=B  info      dmarc-removed-tag  Uses the pct tag, which RFC 9989 removed.
mozilla.org  B      email=A,tls=A,web=B  warning   web-hsts           Strict-Transport-Security has a max-age under a year.
mozilla.org  B      email=A,tls=A,web=B  warning   web-csp            Content-Security-Policy allows unsafe-eval.
...
```

| Flag | Meaning |
| --- | --- |
| `-f file` | Read domains from `file`, one per line, after any given as arguments. `-` reads stdin. |
| `-permute` | Also generate lookalike permutations of each domain. |
| `-lookup` | Find which permutations of each domain exist, using DNS only. It makes about 2 lookups per permutation, so roughly 400 per domain, which takes about 4 seconds at the default `-rate`. |
| `-registration` | Also compare each lookalike's registration with the original's, and rank them. Implies `-lookup`. It makes a request per lookalike at up to 10 a second per registry, so a well-known domain takes about 30 seconds in all. |
| `-suspicious` | Only show lookalikes ranked `medium` or `high`. Implies `-registration`. |
| `-checks list` | Comma-separated areas to check and grade: `email`, `tls`, and `web`. Off by default, since they make DNS lookups and web requests. |
| `-o format` | `json` (default, one object per line), `pretty` (indented JSON), or `text` (aligned columns, one row per domain, or per permutation with `-permute`, per finding with `-checks`, or per lookalike with `-lookup` or `-registration`). Text can't show `-checks` with `-permute` or `-lookup`. Text is aligned in blocks of 1000 rows, so memory stays bounded on large inputs. |
| `-workers number` | Domains to analyze at once. Defaults to the number of CPUs, 16 with `-checks`, or 8 with `-lookup`, where each domain already makes many lookups at once. |
| `-unordered` | Print results as they finish, instead of in input order. |
| `-timeout time` | Time allowed for the checks on one domain. Defaults to 10s, or 10m with `-lookup`, since most of its time is spent waiting behind `-rate`. |
| `-rate number` | DNS lookups and web requests per second, or 0 for no limit. Defaults to 100. |
| `-resolver host` | DNS server to use instead of the system's, as `host` or `host:port`, including for web requests. Home routers often can't handle the large responses of big domains, which then show as `unknown`. |

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
