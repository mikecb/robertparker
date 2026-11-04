package robertparker

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

//Email checks: SPF here, and DMARC in dmarc.go. They only read public DNS records.

const (
	// AreaEmail is the area of the email checks.
	AreaEmail = "email"

	rfcSPF = "RFC 7208"

	// spfLookupLimit is how many DNS-querying terms an SPF evaluation may use before it fails (RFC 7208 section 4.6.4).
	spfLookupLimit = 10
)

// Resolver looks up DNS records. net.DefaultResolver is one, and tests use a fake.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// EmailAnalyzer returns an Analyzer that checks a domain's SPF and DMARC records, and adds Findings. It checks the
// registrable domain, since that's where these records are normally published, not any subdomain that was given.
// Every lookup goes through limiter, which can be nil. A lookup that fails, as opposed to finding nothing, adds a
// SeverityUnknown finding and returns an error, so that a network problem is never reported as a missing record.
func EmailAnalyzer(resolver Resolver, limiter *Limiter) Analyzer {
	return func(ctx context.Context, d *Domain) error {
		name := d.registrable()
		if name == "" {
			return nil
		}
		d.Checked(AreaEmail)
		c := emailChecker{resolver: resolver, limiter: limiter, domain: d}
		return errors.Join(c.checkSPF(ctx, name), c.checkDMARC(ctx, name))
	}
}

// emailChecker is the state of checking one domain.
type emailChecker struct {
	resolver Resolver
	limiter  *Limiter
	domain   *Domain
}

// add records a finding about the domain's email.
func (c *emailChecker) add(check string, severity Severity, standard, message string) {
	c.domain.addFinding(AreaEmail, check, severity, standard, message)
}

// txt returns the TXT records at name. Finding none isn't an error, but a failed lookup is.
func (c *emailChecker) txt(ctx context.Context, name string) ([]string, error) {
	var records []string
	err := c.limiter.Do(ctx, func(ctx context.Context) error {
		var err error
		records, err = c.resolver.LookupTXT(ctx, name)
		return err
	})
	if isNotFound(err) {
		return nil, nil
	}
	return records, err
}

// spfRecords returns the SPF records among the TXT records at name.
func (c *emailChecker) spfRecords(ctx context.Context, name string) ([]string, error) {
	records, err := c.txt(ctx, name)
	if err != nil {
		return nil, err
	}
	var spf []string
	for _, r := range records {
		if len(r) >= 6 && strings.EqualFold(r[:6], "v=spf1") && (len(r) == 6 || r[6] == ' ') {
			spf = append(spf, r)
		}
	}
	return spf, nil
}

// checkSPF checks the SPF record at name.
func (c *emailChecker) checkSPF(ctx context.Context, name string) error {
	records, err := c.spfRecords(ctx, name)
	if err != nil {
		c.add("spf-record", SeverityUnknown, rfcSPF, fmt.Sprintf("Couldn't look up the SPF record of %s: %v", name, err))
		return fmt.Errorf("SPF lookup: %w", err)
	}
	switch len(records) {
	case 0:
		c.add("spf-record", SeverityFailure, rfcSPF, "No SPF record, so anyone can claim to send mail from this domain.")
		return nil
	case 1:
	default:
		c.add("spf-record", SeverityFailure, rfcSPF, fmt.Sprintf("%d SPF records, which makes SPF fail. There must be exactly one.", len(records)))
		return nil
	}

	w := spfWalk{checker: c, seen: map[string]bool{strings.ToLower(name): true}}
	if err := w.walk(ctx, name, records[0]); err != nil {
		c.add("spf-lookups", SeverityUnknown, rfcSPF, fmt.Sprintf("Couldn't follow the includes of %s: %v", name, err))
		return fmt.Errorf("SPF lookup: %w", err)
	}
	if w.syntaxError != "" {
		c.add("spf-syntax", SeverityFailure, rfcSPF, w.syntaxError)
	}
	if w.lookups > spfLookupLimit {
		c.add("spf-lookups", SeverityFailure, rfcSPF, fmt.Sprintf("Needs more than the limit of %d DNS lookups, which makes SPF fail.", spfLookupLimit))
	}
	if w.usesPtr {
		c.add("spf-ptr", SeverityWarning, rfcSPF, "Uses the ptr mechanism, which RFC 7208 says not to use.")
	}
	for _, broken := range w.broken {
		c.add("spf-include", SeverityFailure, rfcSPF, broken)
	}
	switch w.all {
	case "-", "~":
	case "+":
		c.add("spf-all", SeverityFailure, rfcSPF, "Ends in +all, which allows anyone to send mail from this domain.")
	case "?":
		c.add("spf-all", SeverityWarning, rfcSPF, "Ends in ?all, which takes no position on other senders.")
	default:
		c.add("spf-all", SeverityWarning, rfcSPF, "Doesn't end in -all or ~all, so other senders aren't rejected.")
	}
	return nil
}

// spfWalk follows an SPF record through its includes and redirects.
type spfWalk struct {
	checker     *emailChecker
	seen        map[string]bool //Domains already followed, since includes can form loops.
	lookups     int             //Terms that need a DNS query.
	usesPtr     bool
	syntaxError string   //The first syntax error in the record being checked.
	broken      []string //Includes and redirects that don't lead to one SPF record.
	all         string   //The qualifier of the "all" that ends the policy, or "" if there isn't one.
}

// walk reads the SPF record of name, and follows it. Only the record at the start and its redirects decide w.all.
func (w *spfWalk) walk(ctx context.Context, name, record string) error {
	var includes []string
	redirect := ""
	hasAll := false
	for _, term := range strings.Fields(record)[1:] {
		t, err := parseSPFTerm(term)
		if err != nil {
			if w.syntaxError == "" {
				w.syntaxError = fmt.Sprintf("Invalid SPF term in %s: %v", name, err)
			}
			continue
		}
		switch t.name {
		case "include":
			w.lookups++
			includes = append(includes, t.value)
		case "a", "mx", "exists":
			w.lookups++
		case "ptr":
			w.lookups++
			w.usesPtr = true
		case "redirect":
			redirect = t.value
		case "all":
			if !hasAll {
				hasAll = true
				w.all = t.qualifier
			}
		}
	}
	if redirect != "" && !hasAll {
		w.lookups++ // A redirect is ignored when the record has an "all".
	} else {
		redirect = ""
	}

	for _, include := range includes {
		all := w.all
		if err := w.follow(ctx, "include", include); err != nil {
			return err
		}
		w.all = all // An include's "all" only decides whether it matches, not how the policy ends.
	}
	if redirect != "" {
		return w.follow(ctx, "redirect", redirect)
	}
	return nil
}

// follow walks the SPF record of the domain an include or redirect names.
func (w *spfWalk) follow(ctx context.Context, how, name string) error {
	key := strings.ToLower(strings.TrimSuffix(name, "."))
	if strings.Contains(name, "%") || w.seen[key] || w.lookups > spfLookupLimit {
		return nil // Macros need a message to expand, and past the limit the result is already known.
	}
	w.seen[key] = true
	records, err := w.checker.spfRecords(ctx, name)
	if err != nil {
		return err
	}
	if len(records) != 1 {
		w.broken = append(w.broken, fmt.Sprintf("The %s of %s finds %d SPF records instead of one, which makes SPF fail.", how, name, len(records)))
		return nil
	}
	return w.walk(ctx, name, records[0])
}

// spfTerm is one mechanism or modifier of an SPF record.
type spfTerm struct {
	qualifier string //"+", "-", "~", or "?". Mechanisms only.
	name      string //The mechanism or modifier, in lowercase.
	value     string //What follows the ":" or "=", if anything.
}

// parseSPFTerm parses and validates one term of an SPF record.
func parseSPFTerm(s string) (spfTerm, error) {
	end := strings.IndexAny(s, ":=/")
	// A modifier is a name, then "=". It can't have a qualifier, and unknown ones are allowed.
	if end > 0 && s[end] == '=' {
		t := spfTerm{name: strings.ToLower(s[:end]), value: s[end+1:]}
		if !isSPFName(t.name) {
			return t, fmt.Errorf("bad modifier %q", s)
		}
		if t.name == "redirect" && t.value == "" {
			return t, fmt.Errorf("%q has no domain", s)
		}
		return t, nil
	}

	t := spfTerm{qualifier: "+"}
	rest := s
	if rest != "" && strings.ContainsRune("+-~?", rune(rest[0])) {
		t.qualifier = rest[:1]
		rest = rest[1:]
	}
	if end = strings.IndexAny(rest, ":/"); end < 0 {
		end = len(rest)
	}
	t.name = strings.ToLower(rest[:end])
	if end < len(rest) && rest[end] == ':' {
		t.value = rest[end+1:]
	}
	switch t.name {
	case "all":
		if end != len(rest) {
			return t, fmt.Errorf("%q can't have a value", s)
		}
	case "a", "mx", "ptr":
	case "include", "exists":
		if t.value == "" {
			return t, fmt.Errorf("%q has no domain", s)
		}
	case "ip4", "ip6":
		address, _, _ := strings.Cut(t.value, "/")
		ip, err := netip.ParseAddr(address)
		if err != nil || (t.name == "ip4") != ip.Is4() {
			return t, fmt.Errorf("%q has a bad address", s)
		}
	default:
		return t, fmt.Errorf("unknown mechanism %q", s)
	}
	return t, nil
}

// isSPFName reports whether s is a valid modifier name: a letter, then letters, digits, "-", "_", or ".".
func isSPFName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		letter := c >= 'a' && c <= 'z'
		if !letter && (i == 0 || !(c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.')) {
			return false
		}
	}
	return s != ""
}
