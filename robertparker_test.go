package robertparker_test

import (
	"encoding/json"
	"fmt"

	"github.com/mikecb/robertparker"
)

var domains = []string{"appspot.com", "www.appspot.com", "www.google.com", "com", "δοκιμή.δοκιμή", "рф", "p1ai", "xn--p1ai", "foo.appspot.com", "1234.elb.amazonaws.com", "12345134123.azr.msnetanalyticsnet.textanalytics.net", "r20---sn-vgqsen7s.googlevideo.com", "a.b.c.d.alphabet.xyz", "d1y6jrbzotnyjg.cloudfront.net", "st14p04sa.guzzoni-apple.com.akadns.net", "1.2.hi.blob", "fake.test.txt", "test.google"}

func ExampleNewDomain() {
	for _, d := range domains {
		domain := robertparker.NewDomain(d)
		robertparker.Entropy(domain)
		out, _ := json.MarshalIndent(domain, "", "	")
		fmt.Println(string(out))
	}
	//Output:
	// {
	// 	"FQDN": "appspot.com",
	// 	"Suffix": "appspot.com",
	// 	"ICANN": false,
	// 	"Entropy": -0,
	// 	"Permutations": null
	// }
	// {
	// 	"FQDN": "appspot.com",
	// 	"Suffix": "appspot.com",
	// 	"ICANN": false,
	// 	"Entropy": -0,
	// 	"Permutations": null
	// }
	// {
	// 	"FQDN": "google.com",
	// 	"Suffix": "com",
	// 	"Secondary": "google",
	// 	"ICANN": true,
	// 	"Entropy": 1.9182958340544893,
	// 	"Permutations": null
	// }
	// {
	// 	"FQDN": "com",
	// 	"Suffix": "com",
	// 	"ICANN": true,
	// 	"Entropy": -0,
	// 	"Permutations": null
	// }
	// {
	// 	"FQDN": "δοκιμή.δοκιμή",
	// 	"Suffix": "xn--jxalpdlp",
	// 	"Secondary": "xn--jxalpdlp",
	// 	"ICANN": false,
	// 	"Entropy": 2.9182958340544896,
	// 	"Permutations": null
	// }
	// {
	// 	"FQDN": "рф",
	// 	"Suffix": "xn--p1ai",
	// 	"ICANN": true,
	// 	"Entropy": -0,
	// 	"Permutations": null
	// }
	// {
	// 	"FQDN": "p1ai",
	// 	"Suffix": "p1ai",
	// 	"ICANN": false,
	// 	"Entropy": -0,
	// 	"Permutations": null
	// }
	// {
	// 	"FQDN": "xn--p1ai",
	// 	"Suffix": "xn--p1ai",
	// 	"ICANN": true,
	// 	"Entropy": -0,
	// 	"Permutations": null
	// }
	// {
	// 	"FQDN": "foo.appspot.com",
	// 	"Suffix": "appspot.com",
	// 	"Secondary": "foo",
	// 	"ICANN": false,
	// 	"Entropy": 0.9182958340544896,
	// 	"Permutations": null
	// }
	// {
	// 	"FQDN": "1234.elb.amazonaws.com",
	// 	"Suffix": "elb.amazonaws.com",
	// 	"Secondary": "1234",
	// 	"ICANN": false,
	// 	"Entropy": 2,
	// 	"Permutations": null
	// }
	// {
	// 	"FQDN": "12345134123.azr.msnetanalyticsnet.textanalytics.net",
	// 	"Suffix": "net",
	// 	"Secondary": "textanalytics",
	// 	"Tertiary": [
	// 		"12345134123",
	// 		"azr",
	// 		"msnetanalyticsnet"
	// 	],
	// 	"ICANN": true,
	// 	"Entropy": 3.9562733121050786,
	// 	"Permutations": null
	// }
	// {
	// 	"FQDN": "r20---sn-vgqsen7s.googlevideo.com",
	// 	"Suffix": "com",
	// 	"Secondary": "googlevideo",
	// 	"Tertiary": [
	// 		"r20---sn-vgqsen7s"
	// 	],
	// 	"ICANN": true,
	// 	"Entropy": 3.699513850319966,
	// 	"Permutations": null
	// }
	// {
	// 	"FQDN": "a.b.c.d.alphabet.xyz",
	// 	"Suffix": "xyz",
	// 	"Secondary": "alphabet",
	// 	"Tertiary": [
	// 		"a",
	// 		"b",
	// 		"c",
	// 		"d"
	// 	],
	// 	"ICANN": true,
	// 	"Entropy": 3.0220552088742005,
	// 	"Permutations": null
	// }
	// {
	// 	"FQDN": "d1y6jrbzotnyjg.cloudfront.net",
	// 	"Suffix": "cloudfront.net",
	// 	"Secondary": "d1y6jrbzotnyjg",
	// 	"ICANN": false,
	// 	"Entropy": 3.521640636343319,
	// 	"Permutations": null
	// }
	// {
	// 	"FQDN": "st14p04sa.guzzoni-apple.com.akadns.net",
	// 	"Suffix": "net",
	// 	"Secondary": "akadns",
	// 	"Tertiary": [
	// 		"st14p04sa",
	// 		"guzzoni-apple",
	// 		"com"
	// 	],
	// 	"ICANN": true,
	// 	"Entropy": 4.1313003425053605,
	// 	"Permutations": null
	// }
	// {
	// 	"FQDN": "1.2.hi.blob",
	// 	"Suffix": "blob",
	// 	"Secondary": "hi",
	// 	"Tertiary": [
	// 		"1",
	// 		"2"
	// 	],
	// 	"ICANN": false,
	// 	"Entropy": 2,
	// 	"Permutations": null
	// }
	// {
	// 	"FQDN": "fake.test.txt",
	// 	"Suffix": "txt",
	// 	"Secondary": "test",
	// 	"Tertiary": [
	// 		"fake"
	// 	],
	// 	"ICANN": false,
	// 	"Entropy": 2.5,
	// 	"Permutations": null
	// }
	// {
	// 	"FQDN": "test.google",
	// 	"Suffix": "google",
	// 	"Secondary": "test",
	// 	"ICANN": true,
	// 	"Entropy": 1.5,
	// 	"Permutations": null
	// }

}

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
