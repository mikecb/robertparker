package robertparker

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

//DMARC checks, following RFC 9989, which replaced RFC 7489, and RFC 9990 for report destinations.

const (
	rfcDMARC        = "RFC 9989"
	rfcDMARCReports = "RFC 9990"
)

// policyStrength orders DMARC policies from weakest to strongest.
var policyStrength = map[string]int{"none": 1, "quarantine": 2, "reject": 3}

// dmarcRecord is a parsed DMARC record.
type dmarcRecord struct {
	domain string            //Where it was found.
	tags   map[string]string //Its tags. Names are in lowercase, and the first of a duplicate wins.
}

// parseDMARC parses a TXT record. It returns nil unless the record starts with the v=DMARC1 tag.
func parseDMARC(domain, s string) *dmarcRecord {
	tags := map[string]string{}
	for i, part := range strings.Split(s, ";") {
		name, value, found := strings.Cut(part, "=")
		name, value = strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(value)
		if i == 0 && (!found || name != "v" || value != "DMARC1") {
			return nil
		}
		if _, repeated := tags[name]; found && !repeated {
			tags[name] = value
		}
	}
	return &dmarcRecord{domain: domain, tags: tags}
}

// dmarcRecords returns the valid DMARC records at name.
func (c *emailChecker) dmarcRecords(ctx context.Context, name string) ([]*dmarcRecord, error) {
	records, err := c.txt(ctx, "_dmarc."+name)
	if err != nil {
		return nil, err
	}
	var valid []*dmarcRecord
	for _, r := range records {
		if d := parseDMARC(name, r); d != nil {
			valid = append(valid, d)
		}
	}
	return valid, nil
}

// findDMARC does the DNS tree walk of RFC 9989 section 4.10. A record at name itself is the policy. Otherwise it walks
// up through the parents, and the policy is the record where it stopped, at a psd=y or psd=n record, or else the record
// with the fewest labels. It returns the number of records at name, so that having several there can be reported.
func (c *emailChecker) findDMARC(ctx context.Context, name string) (*dmarcRecord, int, error) {
	records, err := c.dmarcRecords(ctx, name)
	if err != nil {
		return nil, 0, err
	}
	if len(records) == 1 {
		return records[0], 1, nil
	}
	atStart := len(records)

	labels := strings.Split(name, ".")
	switch {
	case len(labels) > 8:
		labels = labels[len(labels)-7:] // Long names skip ahead, which keeps the walk to 8 queries.
	default:
		labels = labels[1:]
	}
	var found *dmarcRecord
	for ; len(labels) > 0; labels = labels[1:] {
		records, err := c.dmarcRecords(ctx, strings.Join(labels, "."))
		if err != nil {
			return nil, atStart, err
		}
		if len(records) != 1 {
			continue
		}
		found = records[0]
		if psd := found.tags["psd"]; psd == "y" || psd == "n" {
			break
		}
	}
	return found, atStart, nil
}

// checkDMARC checks the DMARC policy that applies to name.
func (c *emailChecker) checkDMARC(ctx context.Context, name string) error {
	record, atStart, err := c.findDMARC(ctx, name)
	if err != nil {
		c.add("dmarc-record", SeverityUnknown, rfcDMARC, fmt.Sprintf("Couldn't look up the DMARC record of %s: %v", name, err))
		return fmt.Errorf("DMARC lookup: %w", err)
	}
	if atStart > 1 {
		c.add("dmarc-record", SeverityFailure, rfcDMARC, fmt.Sprintf("%d DMARC records at _dmarc.%s, so receivers discard them all.", atStart, name))
		return nil
	}
	if record == nil {
		c.add("dmarc-record", SeverityFailure, rfcDMARC, "No DMARC record, so receivers have no policy for mail that fails authentication.")
		return nil
	}

	inherited := record.domain != name
	if inherited {
		c.add("dmarc-record", SeverityInfo, rfcDMARC, fmt.Sprintf("No record of its own, so the policy comes from %s.", record.domain))
	}
	c.checkDMARCPolicy(record, inherited)
	if record.tags["t"] == "y" {
		c.add("dmarc-testing", SeverityWarning, rfcDMARC, "In test mode (t=y), so receivers apply the policy one level lower.")
	}
	for _, tag := range []string{"pct", "rf", "ri"} {
		if _, ok := record.tags[tag]; ok {
			c.add("dmarc-removed-tag", SeverityInfo, rfcDMARC, fmt.Sprintf("Uses the %s tag, which RFC 9989 removed.", tag))
		}
	}
	return c.checkDMARCReports(ctx, record)
}

// checkDMARCPolicy checks what a record tells receivers to do with mail that fails.
func (c *emailChecker) checkDMARCPolicy(record *dmarcRecord, inherited bool) {
	p := record.tags["p"]
	sp, hasSP := record.tags["sp"]
	np, hasNP := record.tags["np"]
	if policyStrength[p] == 0 || (hasSP && policyStrength[sp] == 0) || (hasNP && policyStrength[np] == 0) {
		// RFC 9989 section 4.10.1: only a valid rua saves a record like this, and then only as p=none.
		if len(validReportURIs(record)) == 0 {
			c.add("dmarc-policy", SeverityFailure, rfcDMARC, "Has a missing or invalid policy and no valid rua, so receivers apply no DMARC processing.")
			return
		}
		c.add("dmarc-policy", SeverityWarning, rfcDMARC, "Has a missing or invalid policy, so receivers act as if it were p=none.")
		return
	}

	// A domain under the one that published the record gets sp, if there is one.
	effective := p
	if inherited && hasSP {
		effective = sp
	}
	if effective == "none" {
		c.add("dmarc-policy", SeverityWarning, rfcDMARC, "Policy is none, which only monitors, and doesn't stop spoofed mail.")
	}
	if hasSP && policyStrength[sp] < policyStrength[p] {
		c.add("dmarc-subdomain-policy", SeverityWarning, rfcDMARC, fmt.Sprintf("sp=%s is weaker than p=%s, so subdomains are less protected.", sp, p))
	}
	subdomains := p
	if hasSP {
		subdomains = sp
	}
	if hasNP && policyStrength[np] < policyStrength[subdomains] {
		c.add("dmarc-subdomain-policy", SeverityWarning, rfcDMARC, fmt.Sprintf("np=%s is weaker than the policy for existing subdomains, so made-up subdomains are less protected.", np))
	}
}

// validReportURIs returns the syntactically valid URIs in a record's rua tag.
func validReportURIs(record *dmarcRecord) []*url.URL {
	var uris []*url.URL
	for _, s := range strings.Split(record.tags["rua"], ",") {
		u, err := url.Parse(strings.TrimSpace(s))
		if err == nil && u.Scheme != "" && (u.Scheme != "mailto" || reportHost(u) != "") {
			uris = append(uris, u)
		}
	}
	return uris
}

// reportHost returns the host of a mailto report URI, without the optional size limit of older records.
func reportHost(u *url.URL) string {
	_, host, found := strings.Cut(u.Opaque, "@")
	if !found {
		return ""
	}
	host, _, _ = strings.Cut(host, "!")
	return strings.ToLower(host)
}

// checkDMARCReports checks that aggregate reports are requested, and that they can be delivered.
func (c *emailChecker) checkDMARCReports(ctx context.Context, record *dmarcRecord) error {
	uris := validReportURIs(record)
	if len(uris) == 0 {
		c.add("dmarc-reporting", SeverityWarning, rfcDMARC, "No valid rua, so there are no reports on who sends mail as this domain.")
		return nil
	}
	policyOrg := organizationalDomain(record.domain)
	for _, u := range uris {
		host := reportHost(u)
		if u.Scheme != "mailto" || host == "" || organizationalDomain(host) == policyOrg {
			continue
		}
		name := record.domain + "._report._dmarc." + host
		if len(name) > 253 {
			c.add("dmarc-report-authorization", SeverityWarning, rfcDMARCReports, fmt.Sprintf("Reports to %s can't be authorized, because the DNS name would be too long.", host))
			continue
		}
		records, err := c.txt(ctx, name)
		if err != nil {
			c.add("dmarc-report-authorization", SeverityUnknown, rfcDMARCReports, fmt.Sprintf("Couldn't check that %s accepts reports: %v", host, err))
			return fmt.Errorf("DMARC report authorization lookup: %w", err)
		}
		authorized := false
		for _, r := range records {
			authorized = authorized || parseDMARC(name, r) != nil
		}
		if !authorized {
			c.add("dmarc-report-authorization", SeverityWarning, rfcDMARCReports, fmt.Sprintf("%s hasn't authorized reports for this domain, so receivers won't send them.", host))
		}
	}
	return nil
}

// organizationalDomain returns name's registrable domain under the public suffix list. RFC 9989 finds the
// Organizational Domain with a DNS tree walk, which is more queries than deciding if two names belong together is
// worth, and the two only differ for domains that publish psd tags that disagree with the list.
func organizationalDomain(name string) string {
	org, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return name
	}
	return org
}
