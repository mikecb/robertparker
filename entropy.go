package robertparker

import (
	"math"
	"sort"
	"strings"
	"unicode/utf8"
)

// shannon calculates the shannon entropy of a given string.
func shannon(d string) float64 {
	frequency := make(map[rune]int)
	t := 0
	for v, w := 0, 0; v < len(d); v += w {
		value, width := utf8.DecodeRuneInString(d[v:])
		w = width
		if _, ok := frequency[value]; ok {
			frequency[value]++
		} else {
			frequency[value] = 1
		}
		t++
	}

	// Sum in a fixed order; map iteration order is random, which changes the low bits of the result.
	runes := make([]rune, 0, len(frequency))
	for r := range frequency {
		runes = append(runes, r)
	}
	sort.Slice(runes, func(a, b int) bool { return runes[a] < runes[b] })

	var entropy float64
	for _, r := range runes {
		k := float64(frequency[r]) / float64(t)
		entropy += float64(k * math.Log2(k)) // explicit conversion prevents fused multiply-add, so results match across architectures
	}
	return entropy * -1
}

// Entropy calculates the shannon entropy of a domain.
func Entropy(d *Domain) float64 {
	//If ICANN = true, uses second-level as well as subdomains, if false, uses only subdomains.
	domainString := d.Secondary + strings.Join(d.Tertiary, "")

	d.Entropy = shannon(domainString)
	return d.Entropy
}
