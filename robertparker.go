package robertparker

import (
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// robertparker grades domains. Get it? Like Domaine like the wine producer. And he grades wines. Yes.

// Domain is a reprisentation of a FQDN split into constituant parts, which other functions can work with.
type Domain struct {
	FQDN         string        //Fully Qualified Domain Name
	Suffix       string        //The domain's publix suffix as defined by publixsuffix.org. Note: public clouds like appspot.com count as a public suffix for these purposes.
	Secondary    string        `json:",omitempty"` //The eTLD+1, e.g.: google.com
	Tertiary     []string      `json:",omitempty"` //A slice of the levels above the TLD+1, e.g. ["foo", "bar"] for foo.bar.google.com
	ICANN        bool          //If a domain is controlled by ICANN, helps us decide which level to use for analysis.
	Entropy      float64       //This might turn into a map if more than one entropy algorithm were to be implemented.
	Permutations []Permutation //A slice of permutations on the registrable domain, for testing for phishing, domain squatting, etc.
	Findings     []Finding     `json:",omitempty"` //What the checks found.
	Grade        string        `json:",omitempty"` //The letter grade from Findings, set by Grade.
}

// registrable returns the domain directly under the public suffix, in punycode, or "" if there isn't one.
func (d *Domain) registrable() string {
	if d.Secondary == "" {
		return ""
	}
	return d.Secondary + "." + d.Suffix
}

// addFinding records a finding about the domain.
func (d *Domain) addFinding(check string, severity Severity, standard, message string) {
	d.Findings = append(d.Findings, Finding{Check: check, Severity: severity, Message: message, Standard: standard})
}

// NewDomain splits a string reprisenting a domain into a struct of its parts.
// Domains are case-insensitive, so it lowercases the input, and drops a trailing dot as in "google.com.".
func NewDomain(s string) *Domain {
	var d Domain

	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
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
