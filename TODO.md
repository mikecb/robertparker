# TODO

## Functionality
- [ ] Better use of Go concurrency patterns when processing large numbers of domains.
- [ ] Built-in CLI. `cli/main.go` currently runs a hard-coded list of domains; read domains from arguments, a file, or stdin, and expose `Entropy` and `Permute`.
- [ ] gRPC-based microservice.

## Domains
- [x] Similarity generation like dnstwist: `Permute` generates lookalike permutations.
- [ ] Similarity lookup like dnstwist: resolve generated permutations to find which are registered.
- [ ] Extend the homoglyph table beyond Latin, so non-Latin labels get homoglyph permutations.

## Abuse
- [ ] Check Safe Browsing and VirusTotal for the domain and subdomains, and return any hits.

## DNS
- [ ] Check DNS, and return all records found.

## Email
- [ ] Check email security related DNS records for best practices.
- [ ] Check mail servers for inclusion on spam blocklists.

## Web
- [ ] Request endpoints and check for best practices.

## TLS
- [ ] Analyze web requests for TLS best practices, like SSL Labs.

## Housekeeping
- [ ] `gofmt` `distance.go`, then add a `gofmt` check to CI.
