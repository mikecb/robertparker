# TODO

## Functionality
- [x] Concurrency for large numbers of domains: `Process` streams domains through a worker pool, and `Limiter` caps calls to network services.
- [x] Speed up `-permute` on big lists. Garbage collection was the main cost, so the CLI now sets a higher GC target (about a third faster, 50-70 MB peak). Moving JSON encoding into the workers was tried and made no measurable difference.
- [ ] Reduce allocations in `Permute`, which are what still limit it from scaling with cores.
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
