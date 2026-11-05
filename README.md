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
| `NewBrandMatcher(brands, owned []string) *BrandMatcher` | Finds names that imitate brands, from certificate logs or a list of names. See [Finding brand imitations](#finding-brand-imitations). |
| `RecordsAnalyzer(server string, limiter *Limiter) Analyzer` | Collects a domain's DNS records into `d.Records`. See [DNS records](#dns-records). |
| `DNSAnalyzer(server string, limiter *Limiter) Analyzer` | Checks the records of a domain's zone, and adds to `d.Findings`. See [DNS checks](#dns-checks). |
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
| `Records` | The DNS records of each type, set by `RecordsAnalyzer`. Left out of JSON if there are none |
| `RecordFailures` | How many record types couldn't be looked up, so `Records` may be missing some |
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

DANE isn't checked yet. When it is, it'll be reported but won't earn a better grade, given its reliability problems, the same as [DNSSEC](#dns-checks).

### TLS and Web checks

`WebAnalyzer` makes ordinary requests to a site, like a browser would, and doesn't probe for anything, unless `Probe` is set (see [Probing TLS](#probing-tls)). It checks the host as given, since each host is its own site, and a registrable domain that isn't reachable gets a second try at `www`. Set `TLS` and `Web` in its `WebConfig` to choose the areas. Both come from the same requests.

| Check | What it looks for |
| --- | --- |
| `tls-https` | The site serves HTTPS |
| `tls-handshake` | The TLS connection works |
| `tls-version` | TLS 1.2 or later, noting TLS 1.2 as information |
| `tls-cipher` | A forward-secret AEAD cipher |
| `tls-post-quantum` | X25519MLKEM768 key exchange. Missing it is a warning, because traffic recorded today could be decrypted by a future quantum computer, and most of the sites sampled already use it |
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

### Probing TLS

A normal connection only shows the best thing a server will do, so a server that also accepts TLS 1.0 or RC4 looks fine. With `Probe` set in `WebConfig`, or `-checks tls-probe`, `WebAnalyzer` also offers a server what it shouldn't accept, and adds to the `tls` area. These are hand-built ClientHellos, because Go's `crypto/tls` can't offer most of this. Each one only reads the server's reply and hangs up, so no handshake finishes.

This is off unless asked for, because it sends what a normal client wouldn't, and this tool may be run on domains the user doesn't own. It makes 10 connections to a site, at most 3 at a time.

| Check | Severity | What it looks for |
| --- | --- | --- |
| `tls-legacy` | Warning | SSL 3.0, TLS 1.0, or TLS 1.1 is accepted (RFC 8996), or 3DES, or RSA key exchange, which isn't forward secret |
| `tls-cipher-broken` | Failure | NULL, export, or RC4 ciphers are accepted |
| `tls-cipher-cbc` | Information | CBC ciphers are accepted |
| `tls-compression` | Failure | TLS compression is accepted, which allows the CRIME attack |
| `tls-renegotiation` | Warning | No secure renegotiation (RFC 5746) |

`tls-legacy` is a warning, not a failure, because modern clients refuse these, so they only reach old devices, and sites keep them for those on purpose, including `google.com` and `cloudflare.com`. All of it is one choice, so it costs once, however many of them a site accepts. CBC is only information because more than half of the sites sampled accept it.

A server that hangs up or stays silent is taken as saying no, since plenty of servers do that instead of sending an alert. The first offer is a reasonable one, and if there's no reply to that, nothing else can be believed, so it's a `SeverityUnknown` finding and the area gets no grade. The same goes for not being able to connect, or running out of time.

Each group of ciphers is offered together, so this shows whether a server accepts any of a group, not which ones. It only looks at port 443, and doesn't test for vulnerabilities in particular servers.

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

This finds squatters on typos of a domain. It doesn't find most phishing, which rarely looks like a typo: `Permute` could generate only 0.1% of the phishing domains naming a major brand in [this evaluation](docs/lookalike-evaluation.md). For that, see [Finding brand imitations](#finding-brand-imitations).

### Finding brand imitations

`BrandMatcher` runs the other way from `Permute`. Rather than guessing names from a brand, it takes names that really exist, and asks if they imitate a brand.

```go
matcher := robertparker.NewBrandMatcher([]string{"paypal.com"}, []string{"paypalobjects.com"})
reader := &robertparker.CTReader{}
for r := range matcher.Find(ctx, reader.Names, nil, 8) {
	fmt.Println(r.Match.Brand, r.Match.Fuzzer, r.Match.ASCII)
}
```

`Find` matches the names from a `NameSource`, and sends each brand and registrable domain once, since a domain can have thousands of names. `CTReader.Names` is one source, and `NamesFrom` reads a list. A match's `Fuzzer` says how it matches, and the first of these that fits is used:

| Kind | Example | Meaning |
| --- | --- | --- |
| `other-suffix` | `paypal.xyz` | The same name on another suffix |
| `brand-domain` | `paypal.com.example.net` | The whole brand domain in a subdomain |
| `homoglyph` | `paypa1.com`, `pay-pal.com` | It reads the same, with lookalike characters or hyphens |
| `typo` | `metanask.com`, `secure-paypall.com` | One edit or swapped letters from the brand, or two for 9 letters or more. It can be a word of a longer name |
| `word` | `paypal-login.com` | The brand is a word of a longer name |
| `embedded` | `paypalsecure.com` | The brand runs into a longer word |
| `subdomain` | `paypal.example.net` | The brand is a word of a subdomain |

Short names match too much, so a few rules keep that down, set by looking at real names. Typos need the brand to have 5 letters, or 6 inside a longer name, and need the same first letter, since nearly all others are real words, like `finance` for `binance` and `email` for `gmail`. Only brands of 6 letters or more count as `embedded`, so `apple` doesn't match `pineapple`. A brand that's also a common word still matches a lot: `office`, `booking`, and `ledger` were 45% of the registered matches in the [evaluation](docs/lookalike-evaluation.md#matching-real-names), so it's worth leaving out brands like them.

Pass the brands' other domains as the second argument, since `amazon.com` otherwise matches all of `amazonaws.com`. Names under a brand or those domains never match. Names under private suffixes do, since anyone can pick `paypal-login.vercel.app`.

`CTReader` follows Certificate Transparency logs, which record nearly every certificate, so new names appear there when their certificates are issued, often before they're used. It reads only the current logs on Chrome's list that publish [names tiles](https://github.com/FiloSottile/sunlight/blob/main/names-tiles.md), which hold just the names, at under 5% of the size of the full entries. 97% of a sample of 15,360 certificates from tiled logs without names tiles were also in the ones it reads, though older-style RFC 6962 logs weren't compared. It reads one tile at a time from each log, skips no entries when a log is down, and checks for new logs daily. It doesn't verify signatures or proofs, which is for checking that logs are honest.

`BrandRanker.Rank` can be passed to `Find` to rate each match with the signs in [Ranking lookalikes](#ranking-lookalikes). It looks up the registrable domain using DNS and RDAP only, and never connects to it. Names under a private suffix are `unknown`, since no registry knows about them. Names that don't exist in DNS are `low`, which matters more than it sounds: `.ph` answers for every name, so about half of what the logs showed in the [evaluation](docs/lookalike-evaluation.md#matching-real-names) was never registered. Use `-registration` or `-suspicious` to set those aside, keeping in mind that `-suspicious` also hides everything `unknown`.

A match is a name to look at, and doesn't prove anything. A certificate only shows that someone controls a name, and a log only shows names with certificates, so a site without HTTPS never appears. Shops and tools that really do work with a brand match too.

### DNS records

`RecordsAnalyzer` collects A, AAAA, CNAME, NS, SOA, MX, TXT, CAA, DS, DNSKEY, HTTPS, and SVCB records into `d.Records`, by type, each value in presentation format, the same as it would be in a zone file. Each type gets its own query, because ANY is unreliable (RFC 8482). It looks up the host as given.

`server` is the DNS server to ask, as `host` or `host:port`. If it's empty, the system's is used. Queries go over UDP, with a retry, and over TCP if the answer doesn't fit. Replies that don't match the query's ID and question are ignored.

These are the records only. To grade them, use `DNSAnalyzer`.

A type that can't be looked up is counted in `d.RecordFailures` and returned as an error, so a missing type can be told apart from one that doesn't exist.

### DNS checks

`DNSAnalyzer` reads a domain's records and adds a `Finding` for each problem. It checks the registrable domain, since that's where the zone starts, so `mail.example.com` is checked as `example.com`. A name with no name servers of its own, or that's a CNAME, isn't a zone, so it gets an information finding and no grade.

| Check | Standard | What it looks for |
| --- | --- | --- |
| `dns-ns-count` | RFC 2182 | More than one name server |
| `dns-ns-network` | RFC 2182 | The name servers aren't all on one /24 network |
| `dns-ns-resolve` | RFC 2182 | Each name server resolves |
| `dns-ns-cname` | RFC 2181 | Name servers aren't CNAMEs |
| `dns-ns-ipv6` | | No name server has an IPv6 address, as information |
| `dns-ns-lame` | RFC 1034 | Each name server answers for the zone with authority, so there's no lame delegation |
| `dns-ns-respond` | RFC 1034 | Each name server replies. No reply is only a warning, since something on the way could have dropped the query |
| `dns-ns-parent` | RFC 1034 | The parent zone and the name servers list the same name servers |
| `dns-ns-serial` | RFC 1034 | Name servers under one domain have the same SOA serial. Across domains, a difference is information, since each DNS provider numbers a zone separately |
| `dns-ns-tcp` | RFC 7766 | Each name server answers over TCP |
| `dns-ns-ipv6-answer` | | Each name server with an IPv6 address answers on it |
| `dns-ns-untested` | | TCP or IPv6 doesn't work from here, as information |
| `dns-soa` | RFC 1912 | There's an SOA record |
| `dns-soa-timers` | RFC 1912 | Retry isn't longer than refresh, and expire is at least the two together. Being outside the suggested ranges is information, since many well-run zones are |
| `dns-address` | RFC 6890 | The A and AAAA records aren't private, loopback, or link-local addresses |
| `dns-mx-cname` | RFC 2181 | Mail servers aren't CNAMEs |
| `dns-caa` | RFC 8659 | CAA records exist, with an `issue` property, so they limit who can issue certificates |
| `dns-caa-critical` | RFC 8659 | No property CAs won't know is marked critical, which stops them issuing |
| `dns-dangling` | | Common subdomains don't have a CNAME that points to a name that doesn't exist. See below for how much that matters |
| `dnssec-status` | RFC 4034 | Whether the zone is signed, as information |
| `dnssec-chain` | RFC 4034 | Keys exist, a DS record at the parent matches one of them, and the signatures validate all the way down from the root |
| `dnssec-signature` | RFC 4034 | Each name server serves a key set signed by a key the DS records point to, and a signed SOA record, with signatures that verify and are in date |
| `dnssec-expiry` | RFC 4034 | Those signatures have at least a tenth of their lifetime left |
| `dnssec-ds-digest` | RFC 9904 | A DS record uses SHA-256 or better |
| `dnssec-algorithm` | RFC 9904 | The keys don't use a deprecated algorithm, like RSA/SHA-1 |

A CNAME that outlives what it points to hands the name to whoever claims the target next, who can then serve anything under the domain. `dns-dangling` is a failure if anyone can claim the target: its domain doesn't seem to be registered, or it's on a service that gives out names, like Azure. It's a warning for any other provider, since that depends on the provider, and information under the domain itself, where nobody else can claim it. Only the zone's owner can list its names, so this looks up about 30 common subdomains and the name given, and a dangling name elsewhere won't be found. It also only finds targets that don't exist, not ones that resolve to a provider's "site not found" page.

DNSSEC never earns credit, given its reliability problems. A zone gets the same grade signed or unsigned, and only loses marks for signing that's broken or weak, since a mistake there takes the whole domain offline.

Signatures are validated here, the way a validating resolver does it, starting from the root zone's published trust anchors, so the result doesn't depend on the resolver in use. Each name server is asked for itself, because one that's stopped getting updates can serve old signatures while the rest are fine. If every server has a problem, validating resolvers will refuse the domain, so that's a failure. If only some do, it's a warning, since a validator can try another. Only the keys and the SOA record are validated in the zone, not every record, and not the proofs that a name doesn't exist. A zone signed with a kind of key Go can't verify, like Ed448, is reported as unchecked, rather than as broken. So is a zone above that can't be checked, for example because the resolver doesn't pass on signatures and the zone above can't be asked instead.

Queries ask a validating resolver for the records even when DNSSEC fails, because otherwise a broken chain looks the same as a server that's down.

Most checks read records through a resolver, so they see what everyone else sees. A resolver hides a broken name server for as long as another one works, so the `dns-ns-` checks also ask each server directly, and ask the zone above for its delegation. These are the same non-recursive queries a resolver sends. TXT is left to the email checks, and HTTPS and SVCB are optional, so they aren't graded.

Direct queries only say something about a name server if they can get out, and many networks block them, or have no IPv6. The zone above is used to see what works from here, so a machine with no IPv6 doesn't make every name server look broken. If no name server can be asked at all, that's more likely the network than the domain, since the domain did resolve, so the area gets no grade. Name servers at private or loopback addresses are reported, and never sent a query, so a list of domains can't reach machines on the local network.

A lookup that fails is reported as a `SeverityUnknown` finding and an error, and the area gets no grade.

A domain takes about 45 queries, so with the default `-rate`, about 2 domains are checked per second, whatever `-workers` is. For long lists, raise `-rate`. Serials can differ briefly while a zone is changing, so a busy zone can get `dns-ns-serial` on one run and not the next.

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

`Suspicion` is a way to sort lookalikes, and doesn't prove anything. The points are judgement, tuned by looking at 20 well-known domains, where about a tenth of lookalikes came out `high`. In a small test, real phishing domains were about three times as likely to rate `high` as ordinary lookalikes, but most still didn't, so a low rating doesn't clear a domain. See the [evaluation](docs/lookalike-evaluation.md). An old domain taken over or re-registered can look innocent or suspicious, and a recent one may be harmless.

Registrations come from a `RegistrationSource`. `RDAP` is one, which asks each registry's server using IANA's list, at up to 10 requests a second per server, and waits when a server says it's getting too many. Registries that aren't on that list have no data, which at the time of writing includes `.io`, `.co`, `.de`, and `.us`.

### Grades

Each area that was checked gets its own grade in `d.Grades`, and `d.Grade` is the worst of them, because a strong area doesn't make up for a weak one: good email settings don't help if the certificate has expired.

An area starts at 100, and loses 40 for a failure and 15 for a warning, or 10 for a warning in `web` and `dns`, which have many more checks and more of them about hardening. Each check costs once, at its worst, however many ways it found a problem. Information findings cost nothing. 90 or more is an A, 80 a B, 70 a C, 60 a D, and anything lower an F.

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

$ robertparker -watch -suspicious -owned owned.txt -o text -f brands.txt
SEEN                 BRAND       KIND  SUSPICION  NAME              ASCII             SOURCE                        REASONS
2026-11-05 16:44:53  paypal.com  word  high       paypal-login.top  paypal-login.top  Let's Encrypt Sycamore2027h1  ...
...

$ robertparker -match new-domains.txt -f brands.txt > matches.jsonl

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
| `-registration` | Also compare each lookalike's registration with the original's, and rank them. Implies `-lookup`, unless used with `-watch` or `-match`. It makes a request per lookalike at up to 10 a second per registry, so a well-known domain takes about 30 seconds in all. |
| `-suspicious` | Only show lookalikes ranked `medium` or `high`. Implies `-registration`. |
| `-watch` | Treat the domains as brands, and follow certificate logs for [names that imitate them](#finding-brand-imitations), printing each as it's found, until interrupted or `-timeout` runs out, which isn't an error. Works with `-registration` and `-suspicious`. Not with `-permute`, `-lookup`, `-records`, or `-checks`. |
| `-match file` | The same, but for the names in `file`, one per line. `-` reads stdin, and then brands have to come from arguments or `-f`. |
| `-owned file` | With `-watch` or `-match`, read the brands' other domains from `file`. Names under them are never reported. |
| `-records` | Collect each domain's DNS records. |
| `-checks list` | Comma-separated areas to check and grade: `dns`, `email`, `tls`, and `web`. `tls-probe` is `tls` plus [offering servers old protocols and weak ciphers](#probing-tls). Off by default, since they make DNS lookups and web requests. |
| `-o format` | `json` (default, one object per line), `pretty` (indented JSON), or `text` (aligned columns, one row per domain, or per permutation with `-permute`, per finding with `-checks`, per record with `-records`, or per lookalike with `-lookup` or `-registration`). Text can only show one of those at a time, but JSON can hold them all. Text is aligned in blocks of 1000 rows, so memory stays bounded on large inputs. With `-watch` or `-match`, text is tab-separated instead, one row per match, written straight away. |
| `-workers number` | Domains to analyze at once. Defaults to the number of CPUs, 16 with `-checks` or `-records`, or 8 with `-lookup`, where each domain already makes many lookups at once, or matches to rank at once with `-watch` or `-match`. |
| `-unordered` | Print results as they finish, instead of in input order. |
| `-timeout time` | Time allowed for the checks on one domain. Defaults to 10s, 30s with `-checks dns` or `tls-probe`, or 10m with `-lookup`, since most of their time is spent waiting behind `-rate` or on servers that stay silent. With `-watch` or `-match`, the time allowed for the whole run, which has no limit by default. |
| `-rate number` | DNS lookups and web requests per second, or 0 for no limit. Defaults to 100. |
| `-resolver host` | DNS server to use instead of the system's, as `host` or `host:port`, including for web requests. Home routers often can't handle the large responses of big domains, which then show as `unknown`. |

The tool runs with a garbage collection target of 400 instead of Go's default of 100, which is about 40% faster with `-permute` for around 25 MB more memory. Set the `GOGC` environment variable to override it.

It exits with 1 if it can't read its input or an analysis fails, 2 for invalid flags, and 130 if interrupted with Ctrl-C, after printing the results it has. Stopping `-watch` isn't an interruption, since it only stops that way.

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
