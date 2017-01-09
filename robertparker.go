package robertparker

import (
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// robertparker grades domains. Get it? Like Domaine like the wine producer. And he grades wines. Yes.

// Domain is a reprisentation of a FQDN split into constituant parts, which other functions can work with.
type Domain struct {
	FQDN         string   `json:""`           //Fully Qualified Domain Name
	Suffix       string   `json:","`          //The domain's publix suffix as defined by publixsuffix.org. Note: public clouds like appspot.com count as a public suffix for these purposes.
	Secondary    string   `json:",omitempty"` //The eTLD+1, e.g.: google.com
	Tertiary     []string `json:",omitempty"` //A slice of the levels above the TLD+1, e.g. ["foo", "bar"] for foo.bar.google.com
	ICANN        bool     `json:","`          //If a domain is controlled by ICANN, helps us decide which level to use for analysis.
	Entropy      float64  `json:","`          //This might turn into a map if more than one entropy algorithm were to be implemented.
	Permutations []string `json:","`          //A slice of permutations on the fqdn, for testing for phishing, domain squatting, etc.
}

// NewDomain splits a string reprisenting a domain into a struct of its parts.
func NewDomain(s string) *Domain {
	var d Domain

	d.FQDN = strings.TrimPrefix(s, "www.")

	punicode, _ := idna.ToASCII(d.FQDN)
	d.Suffix, d.ICANN = publicsuffix.PublicSuffix(punicode)

	eTLDPlusOne, _ := publicsuffix.EffectiveTLDPlusOne(punicode)
	d.Secondary = strings.Trim(strings.TrimSuffix(eTLDPlusOne, d.Suffix), ".")

	if punicode == d.Suffix || punicode == eTLDPlusOne {
		d.Tertiary = nil
	} else {
		ter := strings.Trim(strings.TrimSuffix(punicode, eTLDPlusOne), ".")
		d.Tertiary = strings.Split(ter, ".")
	}
	return &d
}
