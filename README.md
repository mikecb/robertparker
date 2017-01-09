robertparker grades domains. Get it? Like Domaine where wine is made. And he grades them...

It performs only a bit of analysis at the moment, including Shannon entropy score on single domains and Levenshtein distance between a set of domains.
I wrote it because I did not find a good library that performed these simple functions that: 1. understands internationalized domain names like pure unicode or punycode domains, and 2. understands the difference in control between public TLDs like .com, and their secondary and tertiary levels, and private platforms like appspot.com where control rests in the third level and below

Usage:
```
package main

import (
	"encoding/json"
	"fmt"

	"github.com/mikecb/robertparker"
)

func main() {
	domains := []string{"appspot.com", "www.appspot.com", "www.google.com", "com", "δοκιμή.δοκιμή", "рф", "p1ai", "xn--p1ai", "foo.appspot.com", "1234.elb.amazonaws.com", "12345134123.azr.msnetanalyticsnet.textanalytics.net", "r20---sn-vgqsen7s.googlevideo.com", "a.b.c.d.alphabet.xyz", "d1y6jrbzotnyjg.cloudfront.net", "st14p04sa.guzzoni-apple.com.akadns.net", "1.2.hi.blob", "fake.test.txt", "test.google"}
	for _, d := range domains {
		domain := robertparker.NewDomain(d)
		robertparker.Entropy(domain)
		out, _ := json.MarshalIndent(domain, "", "	")
		fmt.Println(string(out))
	}
}
```

Future plans:

Functionality:
Better use of golang concurrency patterns when processing large numbers of domains.
Built-in cli.
GRPC-based microservice.

Domains
Similarity generation and lookup like dnstwist.

Abuse
Check safebrowsing and virustotal links for the domain and subdomains, and return any hits.

DNS
Check DNS, return all found records.

Email
Check email security related DNS records for best practices.
Check mail servers for inclusion on spam/blacklists.

Web
Request endpoints and check for best practices.

TLS
Analyze web request for TLS best practices, like SSL Labs.
