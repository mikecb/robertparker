package main

import (
	"fmt"

	"github.com/mikecb/robertparker"
)

func main() {
	d := []string{"com", "δοκιμή.δοκιμή", "рф", "p1ai", "xn--p1ai", "foo.appspot.com", "1234.elb.amazonaws.com", "12345134123.azr.msnetanalyticsnet.textanalytics.net", "r20---sn-vgqsen7s.googlevideo.com", "a.b.c.d.alphabet.xyz", "d1y6jrbzotnyjg.cloudfront.net", "st14p04sa.guzzoni-apple.com.akadns.net", "1.2.hi.blob", "fake.test.txt", "test.google"}
	for _, domain := range d {
		dom := robertparker.SplitDomain(domain)
		doment := robertparker.Entropy(dom)
		fmt.Printf("Domain: %s\n%+v\nEntropy: %v\n\n", domain, dom, doment)
	}
}
