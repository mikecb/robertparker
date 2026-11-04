package robertparker

import (
	"strings"
	"sync"

	"golang.org/x/net/idna"
)

//Permutation functions that generate lookalike domains, for testing for phishing, domain squatting, etc.

// Permutation is a lookalike of a domain, and the fuzzer that generated it.
type Permutation struct {
	Fuzzer string //The kind of permutation, e.g. "omission" or "homoglyph".
	Domain string //The permuted domain, in Unicode.
	ASCII  string //The permuted domain, in punycode, as it would be registered or looked up.
}

// Permute generates lookalikes of a domain's registrable label, the one directly under the public suffix:
// "google" in www.google.com, or "foo" in bar.foo.appspot.com. Every result is valid for registration under IDNA2008.
func Permute(d *Domain) []Permutation {
	d.Permutations = nil
	if d.Secondary == "" {
		return nil
	}
	label, original := d.Secondary, d.Secondary+"."+d.Suffix
	if !plainRegistrable(original) {
		var err error
		if label, err = idna.ToUnicode(d.Secondary); err != nil {
			return nil
		}
		if original, err = idna.Registration.ToASCII(label + "." + d.Suffix); err != nil {
			return nil
		}
	}

	p := permuters.Get().(*permuter)
	defer permuters.Put(p)
	p.reset(label, d.Suffix, original)
	for _, f := range fuzzers {
		p.fuzzer = f.name
		f.fn(p)
	}
	if d.ICANN {
		p.fuzzer = "tld-swap"
		for _, tld := range swapTLDs {
			if tld != d.Suffix {
				p.suffix = tld
				p.emit(label)
			}
		}
	}
	if len(p.out) > 0 {
		d.Permutations = p.out
	}
	p.out = nil
	return d.Permutations
}

// permuter holds the state of one call to Permute. It is pooled, because its buffers are the bulk of what Permute
// would otherwise allocate.
type permuter struct {
	label  string          //The label being permuted, in Unicode.
	runes  []rune          //The characters of label.
	off    []int           //The byte offset in label of each character, then the length of label.
	suffix string          //The public suffix to put after each candidate.
	fuzzer string          //The fuzzer now running.
	buf    []byte          //The candidate being built.
	seen   map[string]bool //Candidates as generated and in punycode, so repeats skip validation.
	out    []Permutation
}

var permuters = sync.Pool{New: func() any { return &permuter{seen: make(map[string]bool, 512)} }}

// reset prepares p for a new label.
func (p *permuter) reset(label, suffix, original string) {
	p.label, p.suffix = label, suffix
	p.runes, p.off = p.runes[:0], p.off[:0]
	for i, r := range label {
		p.runes = append(p.runes, r)
		p.off = append(p.off, i)
	}
	p.off = append(p.off, len(label))
	clear(p.seen)
	p.seen[original] = true
	p.out = make([]Permutation, 0, 32*len(p.runes)+48)
}

// emit joins parts into a candidate label, and adds it to the results if it is new and valid. Nothing is allocated
// for a repeat.
func (p *permuter) emit(parts ...string) {
	p.buf = p.buf[:0]
	for _, part := range parts {
		p.buf = append(p.buf, part...)
	}
	p.buf = append(p.buf, '.')
	p.buf = append(p.buf, p.suffix...)
	if p.seen[string(p.buf)] {
		return
	}
	candidate := string(p.buf)
	p.seen[candidate] = true
	if plainRegistrable(candidate) {
		p.out = append(p.out, Permutation{Fuzzer: p.fuzzer, Domain: candidate, ASCII: candidate})
		return
	}
	ascii, err := idna.Registration.ToASCII(candidate)
	if err != nil || (ascii != candidate && p.seen[ascii]) {
		return
	}
	p.seen[ascii] = true
	unicode, _ := idna.ToUnicode(ascii)
	p.out = append(p.out, Permutation{Fuzzer: p.fuzzer, Domain: unicode, ASCII: ascii})
}

// replace emits the label with the character at i replaced by s.
func (p *permuter) replace(i int, s string) {
	p.emit(p.label[:p.off[i]], s, p.label[p.off[i+1]:])
}

// insert emits the label with s inserted before the character at i.
func (p *permuter) insert(i int, s string) {
	p.emit(p.label[:p.off[i]], s, p.label[p.off[i]:])
}

// plainRegistrable reports whether s is certainly valid for registration under IDNA2008, and unchanged by it, without
// the cost of running IDNA. It only looks at lowercase letters, digits, hyphens, and dots, in labels of a valid length
// that don't start or end with a hyphen. Anything else, including any "--" and so all punycode, gets false, which only
// means it needs the full check. Most permutations are plain ASCII.
func plainRegistrable(s string) bool {
	if len(s) > 253 {
		return false
	}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if n := i - start; n == 0 || n > 63 || s[start] == '-' || s[i-1] == '-' {
				return false
			}
			start = i + 1
			continue
		}
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && (c != '-' || (i > 0 && s[i-1] == '-')) {
			return false
		}
	}
	return true
}

// fuzzers run in this order, so output is deterministic. Each emits candidate labels.
var fuzzers = []struct {
	name string
	fn   func(*permuter)
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
func addition(p *permuter) {
	for _, c := range "abcdefghijklmnopqrstuvwxyz0123456789" {
		p.emit(p.label, string(c))
	}
}

// bitsquatting flips each bit of each ASCII character, keeping results that are still valid hostname characters.
func bitsquatting(p *permuter) {
	for i, c := range p.runes {
		if c > 127 {
			continue
		}
		for b := 0; b < 8; b++ {
			f := c ^ (1 << uint(b))
			if (f >= 'a' && f <= 'z') || (f >= '0' && f <= '9') || f == '-' {
				p.replace(i, string(f))
			}
		}
	}
}

// homoglyph replaces one character, or one multi-character sequence like "rn", with something that looks like it.
func homoglyph(p *permuter) {
	for i, c := range p.runes {
		for _, g := range homoglyphs[c] {
			p.replace(i, g)
		}
	}
	s := p.label
	for _, h := range sequenceHomoglyphs {
		for i := 0; ; i++ {
			j := strings.Index(s[i:], h[0])
			if j < 0 {
				break
			}
			i += j
			p.emit(s[:i], h[1], s[i+len(h[0]):])
		}
	}
}

// hyphenation inserts a hyphen between two characters.
func hyphenation(p *permuter) {
	for i := 1; i < len(p.runes); i++ {
		p.insert(i, "-")
	}
}

// insertion inserts a neighbouring keyboard key before or after each character.
func insertion(p *permuter) {
	for i, c := range p.runes {
		for _, k := range qwerty[c] {
			p.insert(i, string(k))
			p.insert(i+1, string(k))
		}
	}
}

// omission drops one character.
func omission(p *permuter) {
	for i := range p.runes {
		p.replace(i, "")
	}
}

// repetition doubles one character.
func repetition(p *permuter) {
	for i := range p.runes {
		p.emit(p.label[:p.off[i+1]], p.label[p.off[i]:])
	}
}

// replacement swaps one character for a neighbouring keyboard key.
func replacement(p *permuter) {
	for i, c := range p.runes {
		for _, k := range qwerty[c] {
			p.replace(i, string(k))
		}
	}
}

// subdomain inserts a dot between two characters, so the first part becomes a subdomain of the rest.
func subdomain(p *permuter) {
	for i := 1; i < len(p.runes); i++ {
		if p.runes[i-1] != '-' && p.runes[i] != '-' {
			p.insert(i, ".")
		}
	}
}

// transposition swaps two adjacent characters.
func transposition(p *permuter) {
	s, off := p.label, p.off
	for i := 0; i < len(p.runes)-1; i++ {
		if p.runes[i] != p.runes[i+1] {
			p.emit(s[:off[i]], s[off[i+1]:off[i+2]], s[off[i]:off[i+1]], s[off[i+2]:])
		}
	}
}

// vowelSwap replaces one vowel with another.
func vowelSwap(p *permuter) {
	for i, c := range p.runes {
		if !strings.ContainsRune("aeiou", c) {
			continue
		}
		for _, v := range "aeiou" {
			if v != c {
				p.replace(i, string(v))
			}
		}
	}
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
