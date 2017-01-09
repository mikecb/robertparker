package main

import (
	"encoding/json"
	"fmt"

	"github.com/mikecb/robertparker"
)

func main() {
	domains := []string{"www.google.com", "com", "δοκιμή.δοκιμή", "рф", "p1ai", "xn--p1ai", "foo.appspot.com", "1234.elb.amazonaws.com", "12345134123.azr.msnetanalyticsnet.textanalytics.net", "r20---sn-vgqsen7s.googlevideo.com", "a.b.c.d.alphabet.xyz", "d1y6jrbzotnyjg.cloudfront.net", "st14p04sa.guzzoni-apple.com.akadns.net", "1.2.hi.blob", "fake.test.txt", "test.google"}
	for _, d := range domains {
		domain := robertparker.NewDomain(d)
		robertparker.Entropy(domain)
		out, _ := json.MarshalIndent(domain, "", "	")
		fmt.Println(string(out))
	}
}
