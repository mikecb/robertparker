package robertparker

import (
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

//robertparker grades domains. Get it? Like Domaine like the wine producer. And he grades wines. Yes.

//Domain is a reprisentation of a FQDN split into constituant parts, which other functions can work with.
type Domain struct {
	Suffix    string   //The domain's publix suffix as defined by publixsuffix.org. Note: public clouds like appspot.com count as a public suffix for these purposes.
	Secondary string   //The eTLD+1, e.g.: google.com
	Tertiary  []string //A slice of the levels above the TLD+1, e.g. ["foo", "bar"] for foo.bar.google.com
	ICANN     bool     //If a domain is controlled by ICANN, in which case we can ignore it from analysis.
}

//SplitDomain splits a string reprisenting a domain into a struct of its pats.
func SplitDomain(s string) Domain {
	var d Domain
	puny, _ := idna.ToASCII(s)
	d.Suffix, d.ICANN = publicsuffix.PublicSuffix(puny)

	sec, _ := publicsuffix.EffectiveTLDPlusOne(puny)
	d.Secondary = strings.Trim(strings.TrimSuffix(sec, d.Suffix), ".")

	if puny == d.Suffix || puny == sec {
		ter := ""
		d.Tertiary = strings.Split(ter, ".")
	} else {
		ter := strings.Trim(strings.TrimSuffix(puny, sec), ".")
		d.Tertiary = strings.Split(ter, ".")
	}
	return d
}
