package robertparker_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/mikecb/robertparker"
	"golang.org/x/net/idna"
)

func ExamplePermute() {
	d := robertparker.NewDomain("www.example.com")
	for _, p := range robertparker.Permute(d) {
		if p.Fuzzer == "transposition" {
			fmt.Println(p.Domain)
		}
	}
	//Output:
	// xeample.com
	// eaxmple.com
	// exmaple.com
	// exapmle.com
	// examlpe.com
	// exampel.com
}

func TestPermuteValid(t *testing.T) {
	for _, s := range domains {
		d := robertparker.NewDomain(s)
		perms := robertparker.Permute(d)
		if !reflect.DeepEqual(perms, d.Permutations) {
			t.Errorf("%s: returned permutations differ from d.Permutations", s)
		}
		original, _ := idna.ToASCII(d.Secondary + "." + d.Suffix)
		seen := map[string]bool{}
		for _, p := range perms {
			if p.ASCII == original {
				t.Errorf("%s: permutations include the original domain", s)
			}
			if seen[p.ASCII] {
				t.Errorf("%s: duplicate permutation %s", s, p.ASCII)
			}
			seen[p.ASCII] = true
			ascii, err := idna.Registration.ToASCII(p.Domain)
			if err != nil || ascii != p.ASCII {
				t.Errorf("%s: %s (%s) is not a valid registrable domain: %v", s, p.Domain, p.ASCII, err)
			}
		}
	}
}

func TestPermuteDeterministic(t *testing.T) {
	a := robertparker.Permute(robertparker.NewDomain("google.com"))
	b := robertparker.Permute(robertparker.NewDomain("google.com"))
	if !reflect.DeepEqual(a, b) {
		t.Error("permutations of google.com differ between runs")
	}
}

func TestPermuteBareSuffix(t *testing.T) {
	for _, s := range []string{"com", "appspot.com", "xn--p1ai"} {
		if p := robertparker.Permute(robertparker.NewDomain(s)); p != nil {
			t.Errorf("%s: want no permutations of a bare public suffix, got %d", s, len(p))
		}
	}
}

func TestPermutePrivateSuffix(t *testing.T) {
	for _, p := range robertparker.Permute(robertparker.NewDomain("bar.foo.appspot.com")) {
		if !strings.HasSuffix(p.ASCII, ".appspot.com") {
			t.Errorf("%s (%s) left the appspot.com suffix", p.ASCII, p.Fuzzer)
		}
		if strings.Contains(p.ASCII, "bar") {
			t.Errorf("%s (%s) kept the subdomain", p.ASCII, p.Fuzzer)
		}
		if p.Fuzzer == "tld-swap" {
			t.Errorf("%s: tld-swap applied to a private suffix", p.ASCII)
		}
	}
}

func TestPermuteKnownLookalikes(t *testing.T) {
	tests := []struct {
		domain, fuzzer, want string
	}{
		{"google.com", "addition", "googles.com"},
		{"google.com", "bitsquatting", "foogle.com"},
		{"google.com", "homoglyph", "g0ogle.com"},
		{"google.com", "homoglyph", "xn--gogle-jye.com"}, // Cyrillic о
		{"google.com", "hyphenation", "goo-gle.com"},
		{"google.com", "insertion", "googhle.com"},
		{"google.com", "omission", "gogle.com"},
		{"google.com", "repetition", "gooogle.com"},
		{"google.com", "replacement", "goigle.com"},
		{"google.com", "subdomain", "goo.gle.com"},
		{"google.com", "transposition", "goolge.com"},
		{"google.com", "vowel-swap", "guogle.com"},
		{"google.com", "tld-swap", "google.net"},
		{"microsoft.com", "homoglyph", "rnicrosoft.com"},
		{"modern.com", "homoglyph", "modem.com"},
		{"foo.appspot.com", "omission", "fo.appspot.com"},
	}
	for _, tt := range tests {
		found := false
		for _, p := range robertparker.Permute(robertparker.NewDomain(tt.domain)) {
			if p.ASCII == tt.want {
				found = true
				if p.Fuzzer != tt.fuzzer {
					t.Errorf("%s: %s came from %s, want %s", tt.domain, tt.want, p.Fuzzer, tt.fuzzer)
				}
			}
		}
		if !found {
			t.Errorf("%s: missing %s permutation %s", tt.domain, tt.fuzzer, tt.want)
		}
	}
}
