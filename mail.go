package robertparker

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
)

//The email checks that aren't about SPF or DMARC: mail servers, parked domains, MTA-STS, TLS-RPT, and DKIM.

const (
	rfcSMTP   = "RFC 5321"
	rfcNullMX = "RFC 7505"
	rfcMTASTS = "RFC 8461"
	rfcTLSRPT = "RFC 8460"
	rfcDKIM   = "RFC 6376"
	rfcDKIMv2 = "RFC 8301"

	// maxMailServers is how many of a domain's mail servers are checked. Domains with more are usually using a big
	// provider, whose servers are all set up the same way.
	maxMailServers = 4

	mtaSTSTimeout = 10 * time.Second
	mtaSTSMaxBody = 64 << 10

	// dkimGoodBits is the RSA key size to recommend (RFC 8301 section 3.2), and dkimMinBits the smallest allowed.
	dkimGoodBits = 2048
	dkimMinBits  = 1024
)

// dkimSelectors are the selectors worth trying. They can't be listed, so these are what the big providers and common
// software use, and not finding a key doesn't mean there isn't one.
var dkimSelectors = []string{"default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "dkim", "mail", "smtp", "mandrill", "mxvault", "protonmail"}

// mx returns the MX records of name. Go returns the good records with an error if some were malformed.
func (c *emailChecker) mx(ctx context.Context, name string) ([]*net.MX, error) {
	var records []*net.MX
	err := c.limiter.Do(ctx, func(ctx context.Context) error {
		var err error
		records, err = c.resolver.LookupMX(ctx, name)
		return err
	})
	if isNotFound(err) || len(records) > 0 {
		return records, nil
	}
	return nil, err
}

// hosts returns the addresses of name, or nothing if it doesn't exist.
func (c *emailChecker) hosts(ctx context.Context, name string) ([]string, error) {
	var addresses []string
	err := c.limiter.Do(ctx, func(ctx context.Context) error {
		var err error
		addresses, err = c.resolver.LookupHost(ctx, name)
		return err
	})
	if isNotFound(err) {
		return nil, nil
	}
	return addresses, err
}

// checkMX checks that mail for the domain has somewhere to go.
func (c *emailChecker) checkMX(ctx context.Context, name string) error {
	records, err := c.mx(ctx, name)
	if err != nil {
		c.add("mx-record", SeverityUnknown, rfcSMTP, fmt.Sprintf("Couldn't look up the mail servers of %s: %v", name, err))
		return fmt.Errorf("MX lookup: %w", err)
	}
	c.mxKnown = true
	for _, r := range records {
		host := strings.ToLower(strings.TrimSuffix(r.Host, "."))
		if host == "" {
			c.nullMX = true
			continue
		}
		c.mxHosts = append(c.mxHosts, host)
	}
	if c.nullMX && len(c.mxHosts) > 0 {
		c.add("mx-null", SeverityWarning, rfcNullMX, "Has a null MX alongside real mail servers. A null MX has to be the only one.")
	}
	var errs []error
	for _, host := range c.mxHosts[:min(len(c.mxHosts), maxMailServers)] {
		errs = append(errs, c.checkMailServer(ctx, host))
	}
	return errors.Join(errs...)
}

// checkMailServer checks that a mail server resolves, and notes if it lacks forward-confirmed reverse DNS. That's only
// information, because receivers check it on servers that send to them, and an MX host may only receive. A failed
// lookup is the same as not finding one, for the same reason.
func (c *emailChecker) checkMailServer(ctx context.Context, host string) error {
	addresses, err := c.hosts(ctx, host)
	if err != nil {
		c.add("mx-resolve", SeverityUnknown, rfcSMTP, fmt.Sprintf("Couldn't look up the mail server %s: %v", host, err))
		return fmt.Errorf("mail server lookup: %w", err)
	}
	if len(addresses) == 0 {
		c.add("mx-resolve", SeverityFailure, rfcSMTP, fmt.Sprintf("The mail server %s doesn't resolve, so mail can't be delivered to it.", host))
		return nil
	}

	address := addresses[0]
	var names []string
	err = c.limiter.Do(ctx, func(ctx context.Context) error {
		var err error
		names, err = c.resolver.LookupAddr(ctx, address)
		return err
	})
	if err == nil {
		for _, name := range names {
			forward, err := c.hosts(ctx, strings.TrimSuffix(name, "."))
			if err == nil && slices.Contains(forward, address) {
				return nil
			}
		}
	}
	c.add("mx-reverse-dns", SeverityInfo, rfcSMTP, fmt.Sprintf("The mail server %s (%s) has no forward-confirmed reverse DNS, which matters if it also sends mail.", host, address))
	return nil
}

// checkParked checks a domain that takes no mail and authorizes no senders. Nobody can legitimately send from it, so it
// should say so, or it's free to be spoofed. A domain with no mail servers that does send mail isn't parked.
func (c *emailChecker) checkParked() {
	if !c.mxKnown || !c.spfKnown || !c.dmarcChecked || len(c.mxHosts) > 0 || c.spfSenders {
		return
	}
	if !c.nullMX {
		c.add("parked-null-mx", SeverityInfo, rfcNullMX, "Takes no mail, and could say so with a null MX.")
	}
	if c.spfAll != "" && c.spfAll != "-" {
		c.add("parked-spf", SeverityWarning, rfcSPF, "Sends no mail, so its SPF record should be v=spf1 -all.")
	}
	if c.dmarcPolicy != "" && c.dmarcPolicy != "reject" {
		c.add("parked-dmarc", SeverityWarning, rfcDMARC, fmt.Sprintf("Sends no mail, so its DMARC policy should be reject, not %s.", c.dmarcPolicy))
	}
}

// receivesMail reports whether there's any point in checking how mail reaches the domain.
func (c *emailChecker) receivesMail() bool {
	return len(c.mxHosts) > 0
}

// checkMTASTS checks a domain's MTA-STS policy, which tells senders to require TLS. Not having one is only information,
// but one that doesn't work can stop mail being delivered.
func (c *emailChecker) checkMTASTS(ctx context.Context, name string) error {
	if !c.receivesMail() {
		return nil
	}
	records, err := c.txt(ctx, "_mta-sts."+name)
	if err != nil {
		c.add("mta-sts", SeverityUnknown, rfcMTASTS, fmt.Sprintf("Couldn't look up the MTA-STS record of %s: %v", name, err))
		return fmt.Errorf("MTA-STS lookup: %w", err)
	}
	valid := 0
	for _, r := range records {
		if strings.HasPrefix(r, "v=STSv1") {
			valid++
		}
	}
	switch {
	case valid == 0:
		c.add("mta-sts", SeverityInfo, rfcMTASTS, "No MTA-STS, so senders can be downgraded to unencrypted delivery.")
		return nil
	case valid > 1:
		c.add("mta-sts", SeverityWarning, rfcMTASTS, "More than one MTA-STS record, so senders ignore them.")
		return nil
	}

	var status int
	var body []byte
	err = c.limiter.Do(ctx, func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, mtaSTSTimeout)
		defer cancel()
		var err error
		status, body, err = c.fetchPolicy(ctx, "https://mta-sts."+name+"/.well-known/mta-sts.txt")
		return err
	})
	var netErr net.Error
	switch {
	case errors.As(err, &netErr) && netErr.Timeout():
		c.add("mta-sts", SeverityUnknown, rfcMTASTS, fmt.Sprintf("Couldn't fetch the MTA-STS policy of %s: %v", name, err))
		return fmt.Errorf("MTA-STS policy: %w", err)
	case err != nil:
		c.add("mta-sts", SeverityWarning, rfcMTASTS, fmt.Sprintf("Publishes an MTA-STS record, but the policy can't be fetched: %v", err))
		return nil
	case status != http.StatusOK:
		c.add("mta-sts", SeverityWarning, rfcMTASTS, fmt.Sprintf("Publishes an MTA-STS record, but fetching the policy gives status %d.", status))
		return nil
	}
	c.checkMTASTSPolicy(body)
	return nil
}

// fetchPolicy gets an MTA-STS policy. Redirects aren't allowed for these (RFC 8461 section 3.3).
func (c *emailChecker) fetchPolicy(ctx context.Context, target string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	client := *c.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, mtaSTSMaxBody))
	return resp.StatusCode, body, err
}

// checkMTASTSPolicy checks the contents of a policy.
func (c *emailChecker) checkMTASTSPolicy(body []byte) {
	version, mode := "", ""
	var patterns []string
	for _, line := range strings.Split(string(body), "\n") {
		key, value, _ := strings.Cut(line, ":")
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "version":
			version = value
		case "mode":
			mode = value
		case "mx":
			patterns = append(patterns, strings.ToLower(value))
		}
	}
	if version != "STSv1" {
		c.add("mta-sts", SeverityWarning, rfcMTASTS, "The MTA-STS policy isn't valid.")
		return
	}
	switch mode {
	case "enforce":
	case "testing", "none":
		c.add("mta-sts", SeverityWarning, rfcMTASTS, fmt.Sprintf("The MTA-STS policy is in %s mode, so it doesn't protect mail.", mode))
	default:
		c.add("mta-sts", SeverityWarning, rfcMTASTS, "The MTA-STS policy has no valid mode.")
		return
	}
	for _, host := range c.mxHosts {
		if !slices.ContainsFunc(patterns, func(p string) bool { return matchesMX(p, host) }) {
			severity := SeverityWarning
			if mode == "enforce" {
				severity = SeverityFailure // Senders following the policy will refuse to deliver to it.
			}
			c.add("mta-sts-mx", severity, rfcMTASTS, fmt.Sprintf("The MTA-STS policy doesn't cover the mail server %s.", host))
		}
	}
}

// matchesMX reports whether an MTA-STS mx pattern covers a host. A wildcard covers one label only.
func matchesMX(pattern, host string) bool {
	if rest, wild := strings.CutPrefix(pattern, "*."); wild {
		_, parent, found := strings.Cut(host, ".")
		return found && parent == rest
	}
	return pattern == host
}

// checkTLSRPT checks for TLS-RPT, which asks senders to report delivery problems. It's only worth having with MTA-STS
// or DANE, so not having it is only information.
func (c *emailChecker) checkTLSRPT(ctx context.Context, name string) error {
	if !c.receivesMail() {
		return nil
	}
	records, err := c.txt(ctx, "_smtp._tls."+name)
	if err != nil {
		c.add("tls-rpt", SeverityUnknown, rfcTLSRPT, fmt.Sprintf("Couldn't look up the TLS-RPT record of %s: %v", name, err))
		return fmt.Errorf("TLS-RPT lookup: %w", err)
	}
	var found []string
	for _, r := range records {
		if strings.HasPrefix(r, "v=TLSRPTv1") {
			found = append(found, r)
		}
	}
	switch {
	case len(found) == 0:
		c.add("tls-rpt", SeverityInfo, rfcTLSRPT, "No TLS-RPT, so nobody hears about mail failing to arrive securely.")
	case len(found) > 1:
		c.add("tls-rpt", SeverityWarning, rfcTLSRPT, "More than one TLS-RPT record, so senders ignore them.")
	case !strings.Contains(found[0], "rua="):
		c.add("tls-rpt", SeverityWarning, rfcTLSRPT, "The TLS-RPT record doesn't say where to send reports.")
	}
	return nil
}

// checkDKIM looks for DKIM keys at common selectors, and checks those it finds. Selectors can't be listed, so not finding
// one is only information, and a failed lookup is the same as not finding one.
func (c *emailChecker) checkDKIM(ctx context.Context, name string) error {
	if !c.spfSenders && !c.receivesMail() {
		return nil
	}
	found := false
	for _, selector := range dkimSelectors {
		records, err := c.txt(ctx, selector+"._domainkey."+name)
		if err != nil {
			continue
		}
		for _, r := range records {
			found = c.checkDKIMKey(selector, r) || found
		}
	}
	if !found {
		c.add("dkim-key", SeverityInfo, rfcDKIM, "No DKIM key at common selectors, though it may use another one.")
	}
	return nil
}

// checkDKIMKey checks a DKIM record, and reports whether it holds a key.
func (c *emailChecker) checkDKIMKey(selector, record string) bool {
	tags := map[string]string{}
	for _, part := range strings.Split(record, ";") {
		key, value, ok := strings.Cut(part, "=")
		if ok {
			tags[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
		}
	}
	key, ok := tags["p"]
	if !ok || key == "" { // An empty key is a revoked one, which is good practice.
		return false
	}
	if strings.Contains(tags["t"], "y") {
		c.add("dkim-testing", SeverityInfo, rfcDKIM, fmt.Sprintf("The DKIM key at %s is in test mode (t=y).", selector))
	}
	if hashes, ok := tags["h"]; ok && !strings.Contains(hashes, "sha256") {
		c.add("dkim-hash", SeverityWarning, rfcDKIMv2, fmt.Sprintf("The DKIM key at %s doesn't allow SHA-256.", selector))
	}
	if keyType := tags["k"]; keyType != "" && keyType != "rsa" {
		return true
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(key), ""))
	if err != nil {
		c.add("dkim-key", SeverityWarning, rfcDKIM, fmt.Sprintf("The DKIM key at %s can't be read.", selector))
		return true
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		if parsed, err = x509.ParsePKCS1PublicKey(der); err != nil {
			c.add("dkim-key", SeverityWarning, rfcDKIM, fmt.Sprintf("The DKIM key at %s can't be read.", selector))
			return true
		}
	}
	public, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return true
	}
	switch bits := public.N.BitLen(); {
	case bits < dkimMinBits:
		c.add("dkim-key", SeverityFailure, rfcDKIMv2, fmt.Sprintf("The DKIM key at %s has only %d bits, so verifiers ignore it.", selector, bits))
	case bits < dkimGoodBits:
		c.add("dkim-key", SeverityWarning, rfcDKIMv2, fmt.Sprintf("The DKIM key at %s has %d bits. Use at least %d.", selector, bits, dkimGoodBits))
	}
	return true
}
