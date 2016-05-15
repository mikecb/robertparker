package robertparker

import (
	"math"
	"strings"
	"unicode/utf8"
)

//Entropy calculates the entropy of a given secondary or tertiary domain.
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

	var entropy float64
	for _, i := range frequency {
		k := float64(i) / float64(t)
		entropy += k * math.Log2(k)
	}
	return entropy * -1
}

//Entropy calculates the shannon entropy of a domain.
func Entropy(d Domain) float64 {
	//If ICANN = true, use Secondary and Tertiary, else use only tertiaries.
	var domainString string
	domainString = d.Secondary + strings.Join(d.Tertiary, "")
	return shannon(domainString)
}
