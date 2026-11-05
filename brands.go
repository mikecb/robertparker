package robertparker

import (
	"bufio"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/text/unicode/norm"
)

//Brand matching runs the other way from Permute. Rather than guessing names from a brand, it takes a name that really
//exists, and asks if it's imitating a brand. docs/lookalike-evaluation.md explains why: only 0.1% of phishing domains
//that name a brand are ones Permute could generate.

// The kinds of match. A name that matches a brand in several ways is reported as the first of these that applies.
const (
	MatchOtherSuffix = "other-suffix" //The same name on another suffix, like paypal.xyz.
	MatchBrandDomain = "brand-domain" //The whole brand domain in a subdomain, like paypal.com.example.net.
	MatchHomoglyph   = "homoglyph"    //It reads the same with lookalike characters, like paypa1.com.
	MatchTypo        = "typo"         //A character or two away, like metanask.com.
	MatchWord        = "word"         //The brand is a word of a longer name, like paypal-login.com.
	MatchEmbedded    = "embedded"     //The brand runs into a longer name, like paypalsecure.com.
	MatchSubdomain   = "subdomain"    //The brand is in a subdomain, like paypal.example.net.
)

const (
	// typoMinLength is the shortest brand to look for typos of. One edit away from a short name is mostly other words.
	typoMinLength = 5

	// typoTwoLength is the shortest brand that two edits can be a typo of.
	typoTwoLength = 9

	// wordTypoMinLength is the shortest brand to look for typos of inside a longer name.
	wordTypoMinLength = 6

	// embeddedMinLength is the shortest brand to look for inside longer words. Shorter ones are inside everything:
	// "apple" in "pineapple", or "chase" in "purchase".
	embeddedMinLength = 6
)

// BrandMatch is a name that seems to imitate a brand. Its Fuzzer says how it matches, and its Domain and ASCII are the
// whole name. Everything else in Lookalike is set by BrandRanker.
type BrandMatch struct {
	Brand  string    //The brand's domain.
	Seen   time.Time `json:",omitzero"`  //When the name was seen, if that's known.
	Source string    `json:",omitempty"` //Where the name was seen, if that's known.
	Lookalike
}

// brand is one domain to look for.
type brand struct {
	domain string //Its registrable domain, in punycode.
	label  string //The part in front of the suffix, in punycode.
	reads  string //label as it reads.
}

// BrandMatcher finds names that imitate a list of brands. It's safe to use from many goroutines.
type BrandMatcher struct {
	brands []brand
	owned  map[string]bool //Registrable domains that are never reported.
}

// NewBrandMatcher returns a matcher for brands, which are domains. Names under owned, or under a brand itself, are left
// alone: large brands have other domains, like amazonaws.com for amazon.com, that match by design.
func NewBrandMatcher(brands, owned []string) *BrandMatcher {
	m := &BrandMatcher{owned: map[string]bool{}}
	for _, domain := range brands {
		if d := NewDomain(domain); d.Secondary != "" {
			m.brands = append(m.brands, brand{domain: d.registrable(), label: d.Secondary, reads: reads(d.Secondary)})
			m.owned[d.registrable()] = true
		}
	}
	for _, domain := range owned {
		if d := NewDomain(domain); d.Secondary != "" {
			m.owned[d.registrable()] = true
		}
	}
	return m
}

// Match returns how name imitates each brand, or nothing if it doesn't. A wildcard is treated as its parent, since
// *.paypal-login.com names that domain.
func (m *BrandMatcher) Match(name string) []BrandMatch {
	name = strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), "."), "*.")
	ascii, err := idna.ToASCII(name)
	if err != nil || ascii == "" {
		return nil
	}
	registrable, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil || m.owned[registrable] {
		return nil // An error means it's a public suffix itself, which nobody can imitate a brand with.
	}
	suffix, _ := publicsuffix.PublicSuffix(ascii)
	n := parsedName{label: strings.TrimSuffix(registrable, "."+suffix)}
	n.reads = reads(n.label)
	n.words = wordsOf(n.reads)
	n.solid = strings.ReplaceAll(n.reads, "-", "")
	if ascii != registrable {
		n.subdomains = strings.TrimSuffix(ascii, registrable)
		n.subdomainWords = wordsOf(reads(n.subdomains))
	}

	var matches []BrandMatch
	for i := range m.brands {
		if kind := m.brands[i].match(&n); kind != "" {
			if len(matches) == 0 {
				name, _ = idna.ToUnicode(ascii)
			}
			matches = append(matches, BrandMatch{Brand: m.brands[i].domain, Lookalike: Lookalike{Fuzzer: kind, Domain: name, ASCII: ascii}})
		}
	}
	return matches
}

// parsedName is a name split up once, since it's compared with every brand.
type parsedName struct {
	label          string   //The part in front of the suffix, in punycode.
	reads          string   //label as it reads.
	solid          string   //reads without hyphens.
	words          []string //The words of reads.
	subdomains     string   //Everything in front of the registrable domain, ending in a dot, in punycode.
	subdomainWords []string //The words of subdomains, as they read.
}

// match returns how a name imitates a brand, or "".
func (b *brand) match(n *parsedName) string {
	if n.label == b.label {
		return MatchOtherSuffix
	}
	if strings.HasPrefix(n.subdomains, b.domain+".") || strings.Contains(n.subdomains, "."+b.domain+".") {
		return MatchBrandDomain
	}
	if n.solid == b.reads {
		return MatchHomoglyph
	}
	if b.isTypo(n.solid, typoMinLength) {
		return MatchTypo
	}
	if slices.Contains(n.words, b.reads) {
		return MatchWord
	}
	for _, word := range n.words {
		if b.isTypo(word, wordTypoMinLength) {
			return MatchTypo
		}
	}
	if len(b.reads) >= embeddedMinLength && strings.Contains(n.solid, b.reads) {
		return MatchEmbedded
	}
	if slices.Contains(n.subdomainWords, b.reads) {
		return MatchSubdomain
	}
	return ""
}

// isTypo reports whether word is a likely typo of a brand, if the brand is at least minLength long. A different first
// letter doesn't count, since nearly all of those are other words: "finance" for "binance", or "email" for "gmail".
func (b *brand) isTypo(word string, minLength int) bool {
	n := len(b.reads)
	if n < minLength || word == b.reads || word == "" || word[0] != b.reads[0] {
		return false
	}
	limit := 1
	if n >= typoTwoLength {
		limit = 2
	}
	gap := len(word) - n
	if gap > limit || -gap > limit {
		return false
	}
	return Levenshtein(word, b.reads) <= limit || isSwap(word, b.reads)
}

// isSwap reports whether two strings differ by one pair of neighboring letters swapped, which is one slip of the fingers,
// but two edits.
func isSwap(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	i := 0
	for i < len(a) && a[i] == b[i] {
		i++
	}
	return i+1 < len(a) && a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:]
}

// wordsOf splits a name as it reads into words.
func wordsOf(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '_' || r == '.' })
}

// reads returns a name as it reads, so that everything that looks alike compares equal: paypa1 and paypal, and Cyrillic
// letters and Latin ones. It's only for comparing, since it also changes letters that are fine, like i to l.
func reads(s string) string {
	if strings.Contains(s, "xn--") {
		if decoded, err := idna.ToUnicode(s); err == nil {
			s = decoded
		}
	}
	var b strings.Builder
	for _, r := range norm.NFD.String(s) {
		if unicode.Is(unicode.Mn, r) {
			continue // Accents.
		}
		if fold, ok := folds[r]; ok {
			b.WriteRune(fold)
		} else {
			b.WriteRune(r)
		}
	}
	return sequences.Replace(b.String())
}

// sequences are the letters that look like one other when side by side.
var sequences = strings.NewReplacer("rn", "m", "vv", "w")

// folds maps each character to the one that stands for everything it looks like.
var folds = buildFolds()

func buildFolds() map[rune]rune {
	folds := map[rune]rune{'0': 'o', '1': 'l', 'i': 'l', '3': 'e', '4': 'a', '5': 's'}
	for letter, lookalikes := range homoglyphs {
		for _, lookalike := range lookalikes {
			// Other plain letters are real letters, not imitations.
			if r := []rune(lookalike); len(r) == 1 && r[0] > unicode.MaxASCII {
				if fold, ok := folds[letter]; ok {
					folds[r[0]] = fold
				} else {
					folds[r[0]] = letter
				}
			}
		}
	}
	return folds
}

// NameSource sends names to emit until it runs out or ctx is done. It can call emit from many goroutines.
type NameSource func(ctx context.Context, emit func(Sighting)) error

// NamesFrom returns a NameSource that reads one name per line from r, skipping blank lines and # comments.
func NamesFrom(r io.Reader) NameSource {
	return func(ctx context.Context, emit func(Sighting)) error {
		s := bufio.NewScanner(r)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				emit(Sighting{Name: line})
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
		return s.Err()
	}
}

// BrandResult is what Find sends: a match, or the error that stopped the search or a match being ranked.
type BrandResult struct {
	Match BrandMatch
	Err   error
}

// brandMemory is how many matches Find remembers before it starts over, which bounds its memory. A match that comes
// back after that is only reported again. Few names match, so this takes a long time to fill.
const brandMemory = 1 << 20

// Find matches the names from source, and sends each brand and registrable domain the first time it matches, since one
// domain can have thousands of names. If rank is set, it runs on workers goroutines, and a slow rank slows the source
// down rather than losing matches. The channel closes once source is finished, or ctx is done.
func (m *BrandMatcher) Find(ctx context.Context, source NameSource, rank func(context.Context, *BrandMatch) error, workers int) <-chan BrandResult {
	matches := make(chan BrandMatch)
	results := make(chan BrandResult)
	send := func(r BrandResult) {
		select {
		case results <- r:
		case <-ctx.Done():
		}
	}

	var mu sync.Mutex
	seen := map[string]bool{}
	first := func(match *BrandMatch) bool {
		registrable, _ := publicsuffix.EffectiveTLDPlusOne(match.ASCII)
		key := match.Brand + " " + registrable
		mu.Lock()
		defer mu.Unlock()
		if seen[key] {
			return false
		}
		if len(seen) >= brandMemory {
			clear(seen)
		}
		seen[key] = true
		return true
	}
	var sourceErr error
	go func() {
		defer close(matches)
		sourceErr = source(ctx, func(s Sighting) {
			for _, match := range m.Match(s.Name) {
				if !first(&match) {
					continue
				}
				match.Seen, match.Source = s.Seen, s.Source
				select {
				case matches <- match:
				case <-ctx.Done():
					return
				}
			}
		})
	}()

	if rank == nil {
		workers = 1 // There's nothing to do at once, and one keeps a list's matches in order.
	}
	var wg sync.WaitGroup
	for range max(workers, 1) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for match := range matches {
				var err error
				if rank != nil {
					err = rank(ctx, &match)
				}
				send(BrandResult{Match: match, Err: err})
			}
		}()
	}
	go func() {
		wg.Wait()
		if sourceErr != nil && !errors.Is(sourceErr, context.Canceled) && !errors.Is(sourceErr, context.DeadlineExceeded) {
			send(BrandResult{Err: sourceErr})
		}
		close(results)
	}()
	return results
}
