robertparker grades domains. Get it? Like Domaine like the wine producer. And he grades wines. Yes.

It performs only a bit of analysis at the moment, including shannon entropy scores on single domains and levenshtein distance between a set of domains.
I wrote it because I did not find a good library that performed these simple functions that: 1. understood internationalized domain names like pure unicode or punycode domains, and 2. understood the difference in control between public TLDs like .com, and their secondary and tertiary domains, and private TLDs like appspot.com and other platforms. THis distinction is important when computing these sort of scores as an input to systems which are trying to determine the control of a given FQDN.

Usage:
```
import "github.com/mikecb/robertparker"

func main() {
	d := []string{"com", "δοκιμή.δοκιμή", "рф", "p1ai", "xn--p1ai", "foo.appspot.com", "1234.elb.amazonaws.com", "12345134123.azr.msnetanalyticsnet.textanalytics.net", "r20---sn-vgqsen7s.googlevideo.com", "a.b.c.d.alphabet.xyz", "d1y6jrbzotnyjg.cloudfront.net", "st14p04sa.guzzoni-apple.com.akadns.net", "1.2.hi.blob", "fake.test.txt", "test.google"}
	for _, domain := range d {
		dom := SplitDomain(domain)
		doment := Entropy(dom)
		fmt.Printf("Domain: %s\n%+v\nEntropy: %v\n\n", domain, dom, doment)
	}
}
```
etc.

Plans:

cli utility functionality, ability to read from/to files as well as std in, daemonize as a microservice and read write output in json. Better tests. Other metrics and comparison functions. Similarity generation and lookup like dnstwist. Better use of golang concurrency patterns when processing large numbers of domains, etc...
