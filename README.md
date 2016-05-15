
Useage:

import "github.com/mikecb/robertparker"

func main() {
	d := []string{"a.b.c.d.alphabet.xyz", "1.2.hi.blob", "fake.test.txt", "test.google"}
	for _, domain := range d {
		dom := SplitDomain(domain)
		fmt.Printf("%v\n", dom)
	}
}
