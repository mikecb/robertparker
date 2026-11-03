package robertparker

import (
	"strings"

	"golang.org/x/net/idna"
)

//Permutation functions that generate lookalike domains, for testing for phishing, domain squatting, etc.

// Permutation is a lookalike of a domain, and the fuzzer that generated it.
type Permutation struct {
	Fuzzer string `json:","` //The kind of permutation, e.g. "omission" or "homoglyph".
	Domain string `json:","` //The permuted domain, in Unicode.
	ASCII  string `json:","` //The permuted domain, in punycode, as it would be registered or looked up.
}

// Permute generates lookalikes of a domain's registrable label, the one directly under the public suffix:
// "google" in www.google.com, or "foo" in bar.foo.appspot.com. Every result is valid for registration under IDNA2008.
func Permute(d *Domain) []Permutation {
	d.Permutations = nil
	if d.Secondary == "" {
		return nil
	}
	label, err := idna.ToUnicode(d.Secondary)
	if err != nil {
		return nil
	}
	original, err := idna.Registration.ToASCII(label + "." + d.Suffix)
	if err != nil {
		return nil
	}

	seen := map[string]bool{original: true}
	add := func(fuzzer, label, suffix string) {
		ascii, err := idna.Registration.ToASCII(label + "." + suffix)
		if err != nil || seen[ascii] {
			return
		}
		seen[ascii] = true
		unicode, _ := idna.ToUnicode(ascii)
		d.Permutations = append(d.Permutations, Permutation{Fuzzer: fuzzer, Domain: unicode, ASCII: ascii})
	}

	for _, f := range fuzzers {
		for _, l := range f.fn([]rune(label)) {
			add(f.name, l, d.Suffix)
		}
	}
	if d.ICANN {
		for _, tld := range swapTLDs {
			if tld != d.Suffix {
				add("tld-swap", label, tld)
			}
		}
	}
	return d.Permutations
}

// fuzzers run in this order, so output is deterministic. Each takes a label and returns candidate labels.
var fuzzers = []struct {
	name string
	fn   func([]rune) []string
}{
	{"addition", addition},
	{"bitsquatting", bitsquatting},
	{"homoglyph", homoglyph},
	{"hyphenation", hyphenation},
	{"insertion", insertion},
	{"omission", omission},
	{"repetition", repetition},
	{"replacement", replacement},
	{"subdomain", subdomain},
	{"transposition", transposition},
	{"vowel-swap", vowelSwap},
}

// addition appends a letter or digit to the label.
func addition(l []rune) []string {
	var out []string
	for _, c := range "abcdefghijklmnopqrstuvwxyz0123456789" {
		out = append(out, string(l)+string(c))
	}
	return out
}

// bitsquatting flips each bit of each ASCII character, keeping results that are still valid hostname characters.
func bitsquatting(l []rune) []string {
	var out []string
	for i, c := range l {
		if c > 127 {
			continue
		}
		for b := 0; b < 8; b++ {
			f := c ^ (1 << uint(b))
			if (f >= 'a' && f <= 'z') || (f >= '0' && f <= '9') || f == '-' {
				out = append(out, replaceAt(l, i, string(f)))
			}
		}
	}
	return out
}

// homoglyph replaces one character, or one multi-character sequence like "rn", with something that looks like it.
func homoglyph(l []rune) []string {
	var out []string
	for i, c := range l {
		for _, g := range homoglyphs[c] {
			out = append(out, replaceAt(l, i, g))
		}
	}
	s := string(l)
	for _, h := range sequenceHomoglyphs {
		for i := 0; ; i++ {
			j := strings.Index(s[i:], h[0])
			if j < 0 {
				break
			}
			i += j
			out = append(out, s[:i]+h[1]+s[i+len(h[0]):])
		}
	}
	return out
}

// hyphenation inserts a hyphen between two characters.
func hyphenation(l []rune) []string {
	var out []string
	for i := 1; i < len(l); i++ {
		out = append(out, string(l[:i])+"-"+string(l[i:]))
	}
	return out
}

// insertion inserts a neighbouring keyboard key before or after each character.
func insertion(l []rune) []string {
	var out []string
	for i, c := range l {
		for _, k := range qwerty[c] {
			out = append(out, string(l[:i])+string(k)+string(l[i:]))
			out = append(out, string(l[:i+1])+string(k)+string(l[i+1:]))
		}
	}
	return out
}

// omission drops one character.
func omission(l []rune) []string {
	var out []string
	for i := range l {
		out = append(out, replaceAt(l, i, ""))
	}
	return out
}

// repetition doubles one character.
func repetition(l []rune) []string {
	var out []string
	for i, c := range l {
		out = append(out, replaceAt(l, i, string(c)+string(c)))
	}
	return out
}

// replacement swaps one character for a neighbouring keyboard key.
func replacement(l []rune) []string {
	var out []string
	for i, c := range l {
		for _, k := range qwerty[c] {
			out = append(out, replaceAt(l, i, string(k)))
		}
	}
	return out
}

// subdomain inserts a dot between two characters, so the first part becomes a subdomain of the rest.
func subdomain(l []rune) []string {
	var out []string
	for i := 1; i < len(l); i++ {
		if l[i-1] != '-' && l[i] != '-' {
			out = append(out, string(l[:i])+"."+string(l[i:]))
		}
	}
	return out
}

// transposition swaps two adjacent characters.
func transposition(l []rune) []string {
	var out []string
	for i := 0; i < len(l)-1; i++ {
		if l[i] != l[i+1] {
			t := append([]rune{}, l...)
			t[i], t[i+1] = t[i+1], t[i]
			out = append(out, string(t))
		}
	}
	return out
}

// vowelSwap replaces one vowel with another.
func vowelSwap(l []rune) []string {
	var out []string
	for i, c := range l {
		if !strings.ContainsRune("aeiou", c) {
			continue
		}
		for _, v := range "aeiou" {
			if v != c {
				out = append(out, replaceAt(l, i, string(v)))
			}
		}
	}
	return out
}

// replaceAt returns l with the character at i replaced by s.
func replaceAt(l []rune, i int, s string) string {
	return string(l[:i]) + s + string(l[i+1:])
}

// qwerty maps each key to its neighbours on a US QWERTY keyboard.
var qwerty = map[rune]string{
	'1': "2q", '2': "3wq1", '3': "4ew2", '4': "5re3", '5': "6tr4", '6': "7yt5", '7': "8uy6", '8': "9iu7", '9': "0oi8", '0': "po9",
	'q': "12wa", 'w': "3esaq2", 'e': "4rdsw3", 'r': "5tfde4", 't': "6ygfr5", 'y': "7uhgt6", 'u': "8ijhy7", 'i': "9okju8", 'o': "0plki9", 'p': "lo0",
	'a': "qwsz", 's': "edxzaw", 'd': "rfcxse", 'f': "tgvcdr", 'g': "yhbvft", 'h': "ujnbgy", 'j': "ikmnhu", 'k': "olmji", 'l': "kop",
	'z': "asx", 'x': "zsdc", 'c': "xdfv", 'v': "cfgb", 'b': "vghn", 'n': "bhjm", 'm': "njk",
}

// homoglyphs maps characters to lookalikes: other Latin letters, digits, accented forms, and letters from other scripts.
var homoglyphs = map[rune][]string{
	'a': {"а", "ɑ", "à", "á", "â", "ä"},      // Cyrillic а, Latin ɑ, à, á, â, ä
	'b': {"d", "lb", "ḃ"},                    // ḃ
	'c': {"с", "ϲ", "ç"},                     // Cyrillic с, Greek ϲ, ç
	'd': {"b", "cl", "ԁ"},                    // Cyrillic ԁ
	'e': {"е", "é", "è", "ê", "ë"},           // Cyrillic е, é, è, ê, ë
	'g': {"q", "ɡ", "ġ"},                     // Latin ɡ, ġ
	'h': {"һ", "lh"},                         // Cyrillic һ
	'i': {"1", "l", "і", "í", "ì", "ï", "ı"}, // Cyrillic і, í, ì, ï, dotless ı
	'j': {"ј"},                               // Cyrillic ј
	'k': {"lc", "κ"},                         // Greek κ
	'l': {"1", "i", "ӏ"},                     // Cyrillic ӏ
	'm': {"rn", "nn"},
	'n': {"m", "ո", "ñ"},           // Armenian ո, ñ
	'o': {"0", "о", "ο", "ö", "ó"}, // Cyrillic о, Greek ο, ö, ó
	'p': {"р", "ρ"},                // Cyrillic р, Greek ρ
	'q': {"g", "ԛ"},                // Cyrillic ԛ
	'r': {"г"},                     // Cyrillic г
	's': {"5", "ѕ"},                // Cyrillic ѕ
	't': {"ţ"},                     // ţ
	'u': {"v", "υ", "ս", "ü", "ú"}, // Greek υ, Armenian ս, ü, ú
	'v': {"u", "ν", "ѵ"},           // Greek ν, Cyrillic ѵ
	'w': {"vv", "ԝ"},               // Cyrillic ԝ
	'x': {"х"},                     // Cyrillic х
	'y': {"у", "ý"},                // Cyrillic у, ý
	'z': {"ż"},                     // ż
	'0': {"o"},
	'1': {"l", "i"},
	'5': {"s"},
}

// sequenceHomoglyphs are multi-character sequences and the single character they look like.
var sequenceHomoglyphs = [][2]string{{"rn", "m"}, {"nn", "m"}, {"vv", "w"}, {"cl", "d"}, {"lc", "k"}}

// swapTLDs are common public suffixes to try in place of the original, for ICANN domains.
var swapTLDs = []string{"com", "net", "org", "info", "biz", "co", "io", "xyz", "app", "dev", "online", "site"}
