# TODO

## Functionality
- [x] Concurrency for large numbers of domains: `Process` streams domains through a worker pool, and `Limiter` caps calls to network services.
- [x] Speed up `-permute` on big lists. `Permute` skips IDNA for plain ASCII candidates and reuses its buffers (about 3× faster, with 60% fewer allocations), JSON encoding runs on the workers through `Options.Encode`, and the CLI sets a higher GC target.
- [ ] Make JSON encoding cheaper. It's now about half of the time spent on the workers with `-permute`.
- [ ] Measure scaling past 4 cores. The development machine stopped at about 4× even on pure arithmetic, so scaling beyond that is untested.
- [x] Built-in CLI: `cmd/robertparker` reads domains from arguments, a file, or stdin, and exposes `Entropy` and `Permute`.
- [ ] gRPC-based microservice.

## Domains
- [x] Similarity generation like dnstwist: `Permute` generates lookalike permutations.
- [x] Similarity lookup like dnstwist: `LookalikeAnalyzer` finds which permutations exist, using DNS only.
- [x] Look up the domain registration of each lookalike and compare it to the canonical domain: `RegistrationAnalyzer` ranks lookalikes using RDAP.
- [ ] Get registration data for TLDs that aren't on IANA's RDAP list, like `.io`, `.co`, `.de`, and `.us`, which are `unknown` for now. That likely means WHOIS.
- [x] Check the ranking against known phishing domains. See [docs/lookalike-evaluation.md](docs/lookalike-evaluation.md): `Permute` could generate only 0.1% of phishing domains that name a brand, and the ranking's signals point the right way, on thin evidence.
- [x] Match a stream of real domain names, like newly issued certificates or new registrations, against brands, rather than guessing names from a brand: `-watch` follows certificate logs, and `-match` reads any list of names.
- [ ] Have `-watch` carry on from where it stopped, rather than from the end of each log.
- [ ] Read certificate logs that don't publish names tiles, including RFC 6962 logs, to reach the certificates only they hold. Full entries cost over 20 times the bandwidth.
- [ ] Rank names under private suffixes like `pages.dev`, which are a large share of what `-watch` finds, and are all `unknown`, since no registry knows about them.
- [ ] Find a better sign than a recent registration for matches from certificate logs, since a new certificate already leans towards new domains.
- [ ] Retest the ranking on phishing domains while they're still live, by collecting them over time from a recent feed, which `-watch` now makes possible. Only 61 of 368 sampled domains still existed.
- [ ] Extend the homoglyph table beyond Latin, so non-Latin labels get homoglyph permutations.

## Abuse
- [ ] Check Safe Browsing and VirusTotal for the domain and subdomains, and return any hits.

## Findings
The DNS, Email, TLS, and Web checks below all need these first. Checks marked (intrusive) send something a normal client wouldn't, so they must stay off unless asked for: this tool runs on lists of domains the user may not own.
- [x] `Finding` type: check ID, severity, message, and the standard it comes from, added to `Domain` by analyzers.
- [x] Grade a domain from its findings, since grading domains is the point of the project.
- [x] CLI flags to choose which checks run: `-checks`, which is off by default. Intrusive checks need to stay opt-in when they arrive.

## DNS
Records:
- [x] Collect A, AAAA, CNAME, NS, SOA, MX, TXT, CAA, DS, DNSKEY, and HTTPS/SVCB records, querying by type because ANY is unreliable (RFC 8482): `RecordsAnalyzer`.

Delegation and zone health, in `DNSAnalyzer`:
- [x] At least two nameservers, on separate networks (RFC 2182). Separate means not on one /24.
- [x] NS records at the parent and in the zone agree, and every nameserver answers for the zone, so there's no lame delegation. Taken together, since each of two DNS providers may list only its own servers.
- [x] SOA serials match across nameservers under one domain. Each DNS provider numbers a zone separately, so across domains a difference is information.
- [x] SOA timers are in sensible ranges (RFC 1912). Contradictions cost a warning, but being outside the ranges is information, since half of the large sites sampled are.
- [x] NS and MX targets resolve, and aren't CNAMEs (RFC 2181).
- [x] A and AAAA records aren't private or loopback addresses.
- [x] Nameservers answer over TCP as well as UDP (RFC 7766).
- [x] Nameservers have IPv6 addresses, as information.
- [x] Nameservers answer over IPv6. Tested against local servers, but not yet live, since the development network has no IPv6.
- [ ] Flag wildcard records.
- [ ] Dangling CNAMEs: targets that don't resolve, or point at unclaimed cloud services, which allows subdomain takeover.

DNSSEC:
Test for DNSSEC and DANE, but they don't earn a better grade, and having them enabled could even count against a domain, given their reliability problems.
- [x] Zone is signed, and a DS record at the parent matches a key in the zone.
- [ ] Signatures validate, along the whole chain.
- [x] Signing algorithm isn't a deprecated one like RSA/SHA-1 (RFC 9904).
- [x] DS digest is SHA-256 or better, not SHA-1.
- [ ] RRSIGs aren't expired or about to expire.
- [ ] NSEC3 uses zero extra iterations and no salt (RFC 9276).

Certificate issuance:
- [x] CAA records restrict which CAs can issue (RFC 8659).

Server exposure:
- [ ] Zone transfers (AXFR) are refused (intrusive).
- [ ] Authoritative nameservers aren't open recursive resolvers (intrusive).
- [ ] Nameservers don't disclose their version through `version.bind` (intrusive).

## Email
Mail exchangers:
- [x] MX records exist and resolve. Domains that send and receive no mail publish a null MX (RFC 7505) and `v=spf1 -all`.
- [x] Note MX hosts without forward-confirmed reverse DNS, as information, since it matters for servers that send, and an MX host may only receive.

SPF (RFC 7208):
- [x] Exactly one SPF record, with valid syntax.
- [x] Ends in `-all` or `~all`, and flag `+all` and `?all`.
- [x] Stays within the limit of 10 DNS lookups, and doesn't use the deprecated `ptr` mechanism.

DKIM (RFC 6376):
- [x] Find keys at common selectors. This is best effort, since selectors can't be listed.
- [x] RSA keys are at least 2048 bits, and SHA-1 isn't allowed (RFC 8301).
- [x] Flag keys in test mode (`t=y`).

DMARC (RFC 9989):
- [x] Exactly one valid record, found with the RFC 9989 DNS tree walk rather than the public suffix list. Deciding if a report destination is external still uses the public suffix list.
- [x] Policy is `quarantine` or `reject`, and flag `none` as monitoring only.
- [x] `sp` and `np` don't weaken the policy for subdomains and non-existent subdomains.
- [x] Flag test mode (`t=y`), and the removed `pct`, `rf`, and `ri` tags.
- [x] `rua` reporting is set, and external report destinations authorize it.
- [x] Parked domains, which take no mail and authorize no senders, have a DMARC policy of `reject` and SPF of `-all`.

Transport:
- [x] MTA-STS: valid TXT record, policy served over HTTPS, and `mode=enforce` (RFC 8461).
- [x] TLS-RPT record is published (RFC 8460).
- [ ] DANE TLSA records for MX hosts on DNSSEC-signed zones (RFC 7672).
- [ ] MX hosts offer STARTTLS, with TLS 1.2 or later and a valid certificate. Many networks block outbound port 25, so this needs to report when it couldn't connect.

Reputation:
- [ ] Check mail servers for inclusion on spam blocklists. Most blocklists refuse queries through public resolvers and have usage terms, so this needs its own resolver and `Limiter`.
- [ ] MX hosts aren't open relays (intrusive). Stop at `RCPT TO`, and never send a message.

## TLS
Applies to HTTPS, and to SMTP through STARTTLS. Based on RFC 9325, Mozilla's TLS recommendations, and NIST SP 800-52r2.

Protocols and ciphers:
- [x] Prober with hand-built ClientHellos, since Go's `crypto/tls` can't offer SSLv3 or export ciphers: `-checks tls-probe`.
- [x] TLS 1.1, 1.0, and SSL are disabled (RFC 8996). A warning, since modern clients refuse them, and sites like google.com keep them for old devices.
- [x] Only forward-secret AEAD ciphers. Flag RSA key exchange, CBC, RC4, 3DES, NULL, and export ciphers. CBC is only information, since more than half of the sites sampled accept it.
- [x] Warn if post-quantum key exchange (X25519MLKEM768) is missing, because of harvest-now-decrypt-later attacks. 57% of the sites sampled already use it. Make it a failure as adoption grows.
- [x] Secure renegotiation is supported (RFC 5746), and TLS compression is off.

Certificate:
- [x] Chain is complete and leads to a trusted root, and the name matches the SAN.
- [x] Not expired, and warn when close to expiry, scaled to the certificate's lifetime.
- [x] Lifetime is within the CA/Browser Forum limit for its issue date: 200 days from March 2026, 100 from March 2027, and 47 from March 2029.
- [x] RSA key of at least 2048 bits, or ECDSA P-256 or better, with a SHA-256 or better signature.
- [x] Has Certificate Transparency SCTs.
- [ ] Not revoked, checked through CRLs or OCSP. Don't require OCSP stapling, since CAs are dropping OCSP.

Known vulnerabilities:
- [ ] Heartbleed, ROBOT, and similar (intrusive).

## Web
Based on the OWASP Secure Headers Project, HTTP Headers Cheat Sheet, and ASVS.

HTTPS:
- [x] HTTP redirects to HTTPS, on the apex and `www`.
- [x] HSTS `max-age` is at least a year, with `includeSubDomains`, and report whether it's eligible for preload.
- [ ] No mixed content on the landing page.

Headers:
- [x] Content-Security-Policy is set, and flag `unsafe-inline`, `unsafe-eval`, and wildcard sources.
- [x] Framing is restricted by CSP `frame-ancestors` or `X-Frame-Options`.
- [x] `X-Content-Type-Options: nosniff`.
- [x] `Referrer-Policy` doesn't leak full URLs across origins.
- [x] `Permissions-Policy` is set.
- [x] `Cross-Origin-Opener-Policy` is set.
- [x] Flag obsolete headers: `Expect-CT`, `Public-Key-Pins`, and `X-XSS-Protection` set to anything but `0`.

Cookies:
- [x] Set with `Secure`, `HttpOnly`, and `SameSite`.

CORS:
- [x] Credentialed responses don't allow a wildcard, or reflect an arbitrary `Origin`.

Information disclosure:
- [x] `Server` and `X-Powered-By` don't reveal versions.
- [x] `/.well-known/security.txt` exists, and hasn't passed its `Expires` date (RFC 9116).
- [ ] Third-party scripts use Subresource Integrity.

Server exposure:
- [ ] `TRACE` and unneeded methods are disabled (intrusive).
- [ ] Directory listing is off (intrusive).
- [ ] Files like `.git/config`, `.env`, and backups aren't exposed (intrusive).

## Housekeeping
- [x] `gofmt` `distance.go`, then add a `gofmt` check to CI.
- [x] `Entropy` returned `-0` when there was nothing to score, which showed up as `"Entropy": -0` in JSON; it now returns `0`.
