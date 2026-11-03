# TODO

## Functionality
- [x] Concurrency for large numbers of domains: `Process` streams domains through a worker pool, and `Limiter` caps calls to network services.
- [ ] Encode CLI output in the workers. JSON encoding and writing happen on one goroutine, which limits `-permute` on big lists: 20,000 domains (426 MB of output) take about 5 s whatever the worker count, though `Process` alone scales from 3.7 s to 1.4 s on 12 cores.
- [x] Built-in CLI: `cmd/robertparker` reads domains from arguments, a file, or stdin, and exposes `Entropy` and `Permute`.
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
- [x] `gofmt` `distance.go`, then add a `gofmt` check to CI.
- [x] `Entropy` returned `-0` when there was nothing to score, which showed up as `"Entropy": -0` in JSON; it now returns `0`.
