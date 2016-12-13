package robertparker_test

//
// import (
// 	"fmt"
//
// 	"github.com/mikecb/robertparker"
// )
//
// var d = []string{"com", "δοκιμή.δοκιμή", "рф", "p1ai", "xn--p1ai", "foo.appspot.com", "1234.elb.amazonaws.com", "12345134123.azr.msnetanalyticsnet.textanalytics.net", "r20---sn-vgqsen7s.googlevideo.com", "a.b.c.d.alphabet.xyz", "d1y6jrbzotnyjg.cloudfront.net", "st14p04sa.guzzoni-apple.com.akadns.net", "1.2.hi.blob", "fake.test.txt", "test.google"}
//
// func ExampleSplitDomain() {
// 	for _, domain := range d {
// 		dom := robertparker.SplitDomain(domain)
// 		fmt.Printf("%+v\n", dom)
// 	}
// 	//Output:
// 	// {FQDN: Suffix:com Secondary: Tertiary:[] ICANN:true Entropy:0 Distance:0}
// 	// {FQDN: Suffix:xn--jxalpdlp Secondary:xn--jxalpdlp Tertiary:[] ICANN:false Entropy:0 Distance:0}
// 	// {FQDN: Suffix:xn--p1ai Secondary: Tertiary:[] ICANN:true Entropy:0 Distance:0}
// 	// {FQDN: Suffix:p1ai Secondary: Tertiary:[] ICANN:false Entropy:0 Distance:0}
// 	// {FQDN: Suffix:xn--p1ai Secondary: Tertiary:[] ICANN:true Entropy:0 Distance:0}
// 	// {FQDN: Suffix:appspot.com Secondary:foo Tertiary:[] ICANN:false Entropy:0 Distance:0}
// 	// {FQDN: Suffix:elb.amazonaws.com Secondary:1234 Tertiary:[] ICANN:false Entropy:0 Distance:0}
// 	// {FQDN: Suffix:net Secondary:textanalytics Tertiary:[12345134123 azr msnetanalyticsnet] ICANN:true Entropy:0 Distance:0}
// 	// {FQDN: Suffix:com Secondary:googlevideo Tertiary:[r20---sn-vgqsen7s] ICANN:true Entropy:0 Distance:0}
// 	// {FQDN: Suffix:xyz Secondary:alphabet Tertiary:[a b c d] ICANN:true Entropy:0 Distance:0}
// 	// {FQDN: Suffix:cloudfront.net Secondary:d1y6jrbzotnyjg Tertiary:[] ICANN:false Entropy:0 Distance:0}
// 	// {FQDN: Suffix:net Secondary:akadns Tertiary:[st14p04sa guzzoni-apple com] ICANN:true Entropy:0 Distance:0}
// 	// {FQDN: Suffix:blob Secondary:hi Tertiary:[1 2] ICANN:false Entropy:0 Distance:0}
// 	// {FQDN: Suffix:txt Secondary:test Tertiary:[fake] ICANN:false Entropy:0 Distance:0}
// 	// {FQDN: Suffix:google Secondary:test Tertiary:[] ICANN:true Entropy:0 Distance:0}
// }
//
// func ExampleLevenshtein() {
// 	d := robertparker.Levenshtein("δοκιμή.δοκιμή", "δδοκιμή.δοκιμή")
// 	e := robertparker.Levenshtein("δοκιμή.δοκιμή", "δοκιμή.δοκιμή")
// 	fmt.Printf("%v %v", d, e)
// 	//Output: 2 0
// }
//
// func ExampleEntropy() {
// 	for _, domain := range d {
// 		dom := robertparker.SplitDomain(domain)
// 		doment := robertparker.Entropy(dom)
// 		fmt.Printf("%.3f\n", doment)
// 	}
// 	//Output:
// 	//-0.000
// 	//2.918
// 	//-0.000
// 	//-0.000
// 	//-0.000
// 	//0.918
// 	//2.000
// 	//3.956
// 	//3.700
// 	//3.022
// 	//3.522
// 	//4.131
// 	//2.000
// 	//2.500
// 	//1.500
//
// }
