package robertparker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

//TLS and Web checks. They come from ordinary requests to a domain's site, like a browser would make. The one exception
//is the prober in tlsprobe.go, which is off unless asked for.

const (
	// AreaTLS is the area of the TLS checks.
	AreaTLS = "tls"
	// AreaWeb is the area of the Web checks.
	AreaWeb = "web"

	stdTLS         = "RFC 9325"
	stdBaseline    = "CA/Browser Forum Baseline Requirements"
	stdPostQuantum = "FIPS 203"
	stdCT          = "RFC 6962"
	stdHSTS        = "RFC 6797"
	stdHeaders     = "OWASP Secure Headers Project"
	stdCookies     = "RFC 6265"
	stdSecurityTx  = "RFC 9116"

	userAgent    = "robertparker (+https://github.com/mikecb/robertparker)"
	corsOrigin   = "https://robertparker.invalid" // An origin no site has reason to allow.
	maxRedirects = 5
	maxBody      = 64 << 10
	yearSeconds  = 31536000
)

// WebConfig configures WebAnalyzer.
type WebConfig struct {
	TLS, Web bool //Which checks to run.

	// Probe adds to the TLS checks by offering a server old protocols and weak ciphers. Unlike the other checks, this is
	// something a normal client wouldn't send, so it's separate.
	Probe bool

	// The rest are for testing, and default to the real thing.
	DialContext  func(ctx context.Context, network, addr string) (net.Conn, error)
	Roots        *x509.CertPool
	Now          func() time.Time
	ProbeTimeout time.Duration
}

// WebAnalyzer returns an Analyzer that requests a domain's site over HTTPS and HTTP, and adds Findings about its
// TLS setup and its HTTP headers. It checks the host as given, since each host is its own site with its own
// certificate. A registrable domain that isn't reachable gets a second try at www. Every request goes through limiter,
// which can be nil.
//
// A domain with no site at all gets no grades for these areas, since there's nothing to grade. A request that fails
// for any other reason adds a SeverityUnknown finding and returns an error.
func WebAnalyzer(config WebConfig, limiter *Limiter) Analyzer {
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.ProbeTimeout == 0 {
		config.ProbeTimeout = probeTimeout
	}
	var ciphers []uint16
	for _, c := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		ciphers = append(ciphers, c.ID)
	}
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DialContext:       config.DialContext,
			DisableKeepAlives: true, // Each host is only visited briefly, so don't keep connections to millions of them.
			ForceAttemptHTTP2: true,
			// Connect to anything, even broken or weak setups, because that's what is being checked. checkCertificate
			// does the verification. It's safe here because nothing sensitive is ever sent.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, CipherSuites: ciphers},
		},
	}
	return func(ctx context.Context, d *Domain) error {
		if d.registrable() == "" {
			return nil
		}
		w := webChecker{config: config, client: client, limiter: limiter, domain: d}
		return w.run(ctx, d.hostname())
	}
}

// webChecker is the state of checking one domain.
type webChecker struct {
	config  WebConfig
	client  *http.Client
	limiter *Limiter
	domain  *Domain
}

// webHop is one response.
type webHop struct {
	url      *url.URL
	response *http.Response
	body     []byte
}

// get makes one request. It doesn't follow redirects.
func (w *webChecker) get(ctx context.Context, target string) (*webHop, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Origin", corsOrigin)
	var hop *webHop
	err = w.limiter.Do(ctx, func(context.Context) error {
		resp, err := w.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		// A body cut short only matters to a browser, so a read error here isn't a failed request.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		hop = &webHop{url: req.URL, response: resp, body: body}
		return nil
	})
	return hop, err
}

// fetch makes a request and follows its redirects. It stops at the last response it can get, and only fails if there
// isn't one.
func (w *webChecker) fetch(ctx context.Context, target string) ([]*webHop, error) {
	var hops []*webHop
	for {
		hop, err := w.get(ctx, target)
		if err != nil {
			if len(hops) > 0 {
				return hops, nil
			}
			return nil, err
		}
		hops = append(hops, hop)
		location, err := hop.response.Location()
		if err != nil || hop.response.StatusCode < 300 || hop.response.StatusCode >= 400 || len(hops) > maxRedirects {
			return hops, nil
		}
		target = location.String()
	}
}

// unreachable reports whether err means there's nothing there, as opposed to something going wrong on the way to it.
func unreachable(err error) bool {
	if isNotFound(err) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial" && !opErr.Timeout()
}

// areas returns the areas being checked.
func (w *webChecker) areas() []string {
	var areas []string
	if w.config.TLS {
		areas = append(areas, AreaTLS)
	}
	if w.config.Web {
		areas = append(areas, AreaWeb)
	}
	return areas
}

// run checks the site of the domain called name.
func (w *webChecker) run(ctx context.Context, name string) error {
	host := name
	hops, err := w.fetch(ctx, "https://"+host+"/")
	if err != nil && unreachable(err) && name == w.domain.registrable() {
		host = "www." + name
		hops, err = w.fetch(ctx, "https://"+host+"/")
	}
	redirects, plainErr := w.reachesHTTPS(ctx, "http://"+host+"/")

	switch {
	case err == nil:
	case unreachable(err) && plainErr == nil:
		for _, area := range w.areas() {
			w.domain.Checked(area)
			w.domain.addFinding(area, area+"-https", SeverityFailure, stdTLS, "The site doesn't serve HTTPS, so its traffic can be read and changed.")
		}
		return nil
	case unreachable(err) && unreachable(plainErr):
		for _, area := range w.areas() {
			w.domain.addFinding(area, area+"-site", SeverityInfo, stdTLS, "No web server found, so there's nothing to check.")
		}
		return nil
	case strings.Contains(err.Error(), "tls: ") || errors.Is(err, http.ErrSchemeMismatch):
		// Something answered, but it can't do TLS, which is the server's fault and not a failed request.
		if w.config.TLS {
			w.domain.Checked(AreaTLS)
			w.domain.addFinding(AreaTLS, "tls-handshake", SeverityFailure, stdTLS, fmt.Sprintf("The TLS connection to %s failed: %v", host, err))
			return nil
		}
		fallthrough
	default:
		for _, area := range w.areas() {
			w.domain.Checked(area)
			w.domain.addFinding(area, area+"-request", SeverityUnknown, stdTLS, fmt.Sprintf("Couldn't request %s: %v", host, err))
		}
		return fmt.Errorf("request to %s: %w", host, err)
	}

	var probeErr error
	if w.config.TLS {
		w.domain.Checked(AreaTLS)
		w.checkTLS(hops[0], host)
		if w.config.Probe {
			probeErr = w.probeTLS(ctx, host)
		}
	}
	if w.config.Web {
		w.domain.Checked(AreaWeb)
		if plainErr == nil && !redirects {
			w.addWeb("web-https-redirect", SeverityWarning, stdHSTS, "HTTP doesn't redirect to HTTPS.")
		}
		w.checkHeaders(hops)
		w.checkSecurityTxt(ctx, hops[len(hops)-1])
	}
	return probeErr
}

// addTLS and addWeb record a finding in their area.
func (w *webChecker) addTLS(check string, severity Severity, standard, message string) {
	w.domain.addFinding(AreaTLS, check, severity, standard, message)
}

func (w *webChecker) addWeb(check string, severity Severity, standard, message string) {
	w.domain.addFinding(AreaWeb, check, severity, standard, message)
}

// checkTLS checks the connection and certificate of the first HTTPS response.
func (w *webChecker) checkTLS(hop *webHop, host string) {
	state := hop.response.TLS
	if state == nil || len(state.PeerCertificates) == 0 {
		w.addTLS("tls-handshake", SeverityUnknown, stdTLS, "The response had no TLS details.")
		return
	}
	switch {
	case state.Version < tls.VersionTLS12:
		w.addTLS("tls-version", SeverityFailure, "RFC 8996", fmt.Sprintf("Negotiated %s, which is deprecated. Use TLS 1.2 or later.", tls.VersionName(state.Version)))
	case state.Version == tls.VersionTLS12:
		w.addTLS("tls-version", SeverityInfo, stdTLS, "Negotiated TLS 1.2 when offered TLS 1.3.")
	}
	if name := tls.CipherSuiteName(state.CipherSuite); state.Version < tls.VersionTLS13 &&
		!(strings.HasPrefix(name, "TLS_ECDHE_") && (strings.Contains(name, "_GCM_") || strings.Contains(name, "CHACHA20"))) {
		w.addTLS("tls-cipher", SeverityWarning, stdTLS, fmt.Sprintf("Negotiated %s, which isn't a forward-secret AEAD cipher.", name))
	}
	// A warning rather than information, because traffic recorded today can be decrypted once there's a large enough
	// quantum computer, and most of the sites sampled already use it. It isn't a failure, since nothing is broken yet.
	if state.CurveID != tls.X25519MLKEM768 {
		w.addTLS("tls-post-quantum", SeverityWarning, stdPostQuantum, "Doesn't use post-quantum key exchange (X25519MLKEM768), so traffic recorded today could be decrypted by a future quantum computer.")
	}
	w.checkCertificate(state, host)
}

// certificateLimit returns the longest a certificate issued at t may last, from CA/Browser Forum ballot SC-081.
func certificateLimit(t time.Time) int {
	for _, limit := range []struct {
		from time.Time
		days int
	}{
		{time.Date(2029, 3, 15, 0, 0, 0, 0, time.UTC), 47},
		{time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC), 100},
		{time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), 200},
	} {
		if !t.Before(limit.from) {
			return limit.days
		}
	}
	return 398
}

// sctExtension is the certificate extension that holds embedded Certificate Transparency timestamps.
var sctExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// checkCertificate verifies the leaf certificate. Each problem gets its own finding, which is why it does this rather
// than letting the connection fail.
func (w *webChecker) checkCertificate(state *tls.ConnectionState, host string) {
	leaf := state.PeerCertificates[0]
	now := w.config.Now()
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)

	// Check the chain as of a time the certificate was valid, so that expiry gets reported once, on its own.
	at := now
	switch {
	case now.After(leaf.NotAfter):
		at = leaf.NotAfter
		w.addTLS("tls-expiry", SeverityFailure, stdTLS, fmt.Sprintf("The certificate expired on %s.", leaf.NotAfter.Format(time.DateOnly)))
	case now.Before(leaf.NotBefore):
		at = leaf.NotBefore
		w.addTLS("tls-expiry", SeverityFailure, stdTLS, fmt.Sprintf("The certificate isn't valid until %s.", leaf.NotBefore.Format(time.DateOnly)))
	case leaf.NotAfter.Sub(now) < lifetime/10:
		w.addTLS("tls-expiry", SeverityWarning, stdTLS, fmt.Sprintf("The certificate expires soon, on %s.", leaf.NotAfter.Format(time.DateOnly)))
	}

	if err := leaf.VerifyHostname(host); err != nil {
		w.addTLS("tls-hostname", SeverityFailure, stdTLS, fmt.Sprintf("The certificate isn't valid for %s.", host))
	}
	intermediates := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}
	trusted := true
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: w.config.Roots, Intermediates: intermediates, CurrentTime: at}); err != nil {
		trusted = false
		w.addTLS("tls-chain", SeverityFailure, stdTLS, fmt.Sprintf("The certificate doesn't chain to a trusted root: %v", err))
	}

	// These two are rules for publicly trusted certificates, so they don't apply to a private one.
	if limit := certificateLimit(leaf.NotBefore); trusted && lifetime > time.Duration(limit)*24*time.Hour {
		w.addTLS("tls-lifetime", SeverityFailure, stdBaseline, fmt.Sprintf("The certificate lasts %d days, over the limit of %d for one issued then.", int(lifetime.Hours()/24), limit))
	}
	hasSCT := len(state.SignedCertificateTimestamps) > 0
	for _, e := range leaf.Extensions {
		hasSCT = hasSCT || e.Id.Equal(sctExtension)
	}
	if trusted && !hasSCT {
		w.addTLS("tls-transparency", SeverityWarning, stdCT, "The certificate has no Certificate Transparency timestamps, so browsers may reject it.")
	}

	switch key := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			w.addTLS("tls-key", SeverityFailure, stdTLS, fmt.Sprintf("The certificate has a %d-bit RSA key. Use at least 2048 bits.", key.N.BitLen()))
		}
	case *ecdsa.PublicKey:
		if key.Curve.Params().BitSize < 256 {
			w.addTLS("tls-key", SeverityFailure, stdTLS, fmt.Sprintf("The certificate has a %d-bit ECDSA key. Use at least 256 bits.", key.Curve.Params().BitSize))
		}
	case ed25519.PublicKey:
	default:
		w.addTLS("tls-key", SeverityWarning, stdTLS, fmt.Sprintf("The certificate has an unusual key type, %s.", leaf.PublicKeyAlgorithm))
	}
	switch leaf.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		w.addTLS("tls-signature", SeverityFailure, stdTLS, fmt.Sprintf("The certificate is signed with %s. Use SHA-256 or better.", leaf.SignatureAlgorithm))
	}
}

// reachesHTTPS follows plain HTTP redirects, and reports whether they lead to HTTPS. Sites often go to www first, so
// the first redirect isn't enough. The error is from the first request, which says if anything is listening.
func (w *webChecker) reachesHTTPS(ctx context.Context, target string) (bool, error) {
	for i := 0; i <= maxRedirects; i++ {
		hop, err := w.get(ctx, target)
		if err != nil {
			if i > 0 {
				err = nil
			}
			return false, err
		}
		location, err := hop.response.Location()
		if err != nil {
			return false, nil
		}
		if location.Scheme == "https" {
			return true, nil
		}
		target = location.String()
	}
	return false, nil
}

// checkHeaders checks the response headers of the final page, apart from those about each response, like HSTS.
func (w *webChecker) checkHeaders(hops []*webHop) {
	first, final := hops[0].response.Header, hops[len(hops)-1]
	h := final.response.Header
	if final.url.Scheme != "https" {
		w.addWeb("web-https-redirect", SeverityFailure, stdHSTS, fmt.Sprintf("HTTPS redirects to %s, which is plain HTTP.", final.url.Redacted()))
	}
	// Sites often redirect to www and set HSTS there, so look at every HTTPS response.
	hsts := ""
	for _, hop := range hops {
		if value := hop.response.Header.Get("Strict-Transport-Security"); value != "" && hop.url.Scheme == "https" && hsts == "" {
			hsts = value
		}
	}
	w.checkHSTS(hsts)
	w.checkCSP(h.Get("Content-Security-Policy"), h.Get("Content-Security-Policy-Report-Only"))

	if !strings.Contains(strings.ToLower(h.Get("Content-Security-Policy")), "frame-ancestors") {
		if xfo := strings.ToUpper(strings.TrimSpace(h.Get("X-Frame-Options"))); xfo != "DENY" && xfo != "SAMEORIGIN" {
			w.addWeb("web-framing", SeverityWarning, stdHeaders, "Nothing stops other sites framing this page. Set CSP frame-ancestors or X-Frame-Options.")
		}
	}
	if !strings.EqualFold(strings.TrimSpace(h.Get("X-Content-Type-Options")), "nosniff") {
		w.addWeb("web-nosniff", SeverityWarning, stdHeaders, "No X-Content-Type-Options: nosniff, so browsers may guess content types.")
	}
	switch strings.ToLower(strings.TrimSpace(h.Get("Referrer-Policy"))) {
	case "unsafe-url", "no-referrer-when-downgrade":
		w.addWeb("web-referrer", SeverityWarning, stdHeaders, "Referrer-Policy sends full URLs to other sites.")
	}
	if h.Get("Permissions-Policy") == "" {
		w.addWeb("web-permissions", SeverityInfo, stdHeaders, "No Permissions-Policy.")
	}
	if h.Get("Cross-Origin-Opener-Policy") == "" {
		w.addWeb("web-coop", SeverityInfo, stdHeaders, "No Cross-Origin-Opener-Policy.")
	}
	for _, name := range []string{"Expect-CT", "Public-Key-Pins"} {
		if h.Get(name) != "" {
			w.addWeb("web-obsolete", SeverityInfo, stdHeaders, fmt.Sprintf("Sends %s, which is obsolete.", name))
		}
	}
	if xss := strings.TrimSpace(h.Get("X-XSS-Protection")); xss != "" && xss != "0" {
		w.addWeb("web-obsolete", SeverityInfo, stdHeaders, "X-XSS-Protection is on. It's obsolete, and should be 0 or left out.")
	}

	if server := h.Get("Server"); strings.ContainsAny(server, "0123456789") {
		w.addWeb("web-disclosure", SeverityInfo, stdHeaders, fmt.Sprintf("The Server header gives a version: %s.", server))
	}
	if powered := h.Get("X-Powered-By"); powered != "" {
		w.addWeb("web-disclosure", SeverityInfo, stdHeaders, fmt.Sprintf("The X-Powered-By header reveals the stack: %s.", powered))
	}

	if origin := first.Get("Access-Control-Allow-Origin"); strings.EqualFold(first.Get("Access-Control-Allow-Credentials"), "true") {
		switch origin {
		case corsOrigin:
			w.addWeb("web-cors", SeverityFailure, stdHeaders, "Allows credentialed requests from any origin, so other sites can read logged-in responses.")
		case "*":
			w.addWeb("web-cors", SeverityWarning, stdHeaders, "Combines a wildcard origin with credentials, which browsers reject.")
		}
	}
	w.checkCookies(hops)
}

// checkHSTS checks a Strict-Transport-Security header.
func (w *webChecker) checkHSTS(value string) {
	if value == "" {
		w.addWeb("web-hsts", SeverityWarning, stdHSTS, "No Strict-Transport-Security, so a first visit can be downgraded to HTTP.")
		return
	}
	maxAge, subdomains, preload := -1, false, false
	for _, directive := range strings.Split(value, ";") {
		name, val, _ := strings.Cut(strings.TrimSpace(directive), "=")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "max-age":
			if n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(val), `"`)); err == nil {
				maxAge = n
			}
		case "includesubdomains":
			subdomains = true
		case "preload":
			preload = true
		}
	}
	if maxAge < yearSeconds {
		w.addWeb("web-hsts", SeverityWarning, stdHSTS, "Strict-Transport-Security has a max-age under a year.")
	}
	if !subdomains {
		w.addWeb("web-hsts", SeverityInfo, stdHSTS, "Strict-Transport-Security doesn't cover subdomains.")
	} else if !preload {
		w.addWeb("web-hsts", SeverityInfo, stdHSTS, "Strict-Transport-Security doesn't opt in to preloading.")
	}
}

// checkCSP checks a Content-Security-Policy header.
func (w *webChecker) checkCSP(policy, reportOnly string) {
	switch {
	case policy == "" && reportOnly != "":
		w.addWeb("web-csp", SeverityWarning, stdHeaders, "Content-Security-Policy is only in report-only mode, so it blocks nothing.")
		return
	case policy == "":
		w.addWeb("web-csp", SeverityWarning, stdHeaders, "No Content-Security-Policy.")
		return
	}
	lower := strings.ToLower(policy)
	// Browsers ignore unsafe-inline in a policy with a nonce or hash, which is how sites stay compatible with old ones.
	strict := strings.Contains(lower, "'nonce-") || strings.Contains(lower, "'sha256-") || strings.Contains(lower, "'sha384-") || strings.Contains(lower, "'sha512-")
	if strings.Contains(lower, "'unsafe-inline'") && !strict {
		w.addWeb("web-csp", SeverityWarning, stdHeaders, "Content-Security-Policy allows unsafe-inline, which defeats most of its protection.")
	}
	if strings.Contains(lower, "'unsafe-eval'") {
		w.addWeb("web-csp", SeverityWarning, stdHeaders, "Content-Security-Policy allows unsafe-eval.")
	}
	for _, directive := range strings.Split(lower, ";") {
		fields := strings.Fields(directive)
		for i := 1; i < len(fields); i++ {
			if fields[i] == "*" && (fields[0] == "default-src" || fields[0] == "script-src") {
				w.addWeb("web-csp", SeverityWarning, stdHeaders, fmt.Sprintf("Content-Security-Policy allows any source in %s.", fields[0]))
			}
		}
	}
}

// checkCookies checks the cookies set on the way to the final page.
func (w *webChecker) checkCookies(hops []*webHop) {
	var insecure, script, sameSite []string
	for _, hop := range hops {
		for _, c := range hop.response.Cookies() {
			if !c.Secure {
				insecure = append(insecure, c.Name)
			}
			if !c.HttpOnly {
				script = append(script, c.Name)
			}
			if c.SameSite == 0 || c.SameSite == http.SameSiteDefaultMode {
				sameSite = append(sameSite, c.Name)
			}
		}
	}
	if len(insecure) > 0 {
		w.addWeb("web-cookies", SeverityWarning, stdCookies, "Cookies without Secure, so they can be sent over HTTP: "+cookieNames(insecure))
	}
	if len(script) > 0 {
		w.addWeb("web-cookies", SeverityInfo, stdCookies, "Cookies without HttpOnly, which scripts can read. That's fine unless they're for sessions: "+cookieNames(script))
	}
	if len(sameSite) > 0 {
		w.addWeb("web-cookies", SeverityInfo, stdCookies, "Cookies without SameSite: "+cookieNames(sameSite))
	}
}

// cookieNames lists names once each, since a site can set a cookie more than once on the way to the final page.
func cookieNames(names []string) string {
	sort.Strings(names)
	return strings.Join(slices.Compact(names), ", ")
}

// checkSecurityTxt checks for a security.txt on the host of the final page. It's a nice to have, so a request that
// fails is the same as not finding one.
func (w *webChecker) checkSecurityTxt(ctx context.Context, final *webHop) {
	target := url.URL{Scheme: final.url.Scheme, Host: final.url.Host, Path: "/.well-known/security.txt"}
	hop, err := w.get(ctx, target.String())
	contact, expires := false, ""
	if err == nil && hop.response.StatusCode == http.StatusOK {
		for s := bufio.NewScanner(bytes.NewReader(hop.body)); s.Scan(); {
			name, value, found := strings.Cut(s.Text(), ":")
			switch {
			case found && strings.EqualFold(name, "Contact"):
				contact = true
			case found && strings.EqualFold(name, "Expires"):
				expires = strings.TrimSpace(value)
			}
		}
	}
	if !contact {
		w.addWeb("web-security-txt", SeverityInfo, stdSecurityTx, "No security.txt, so researchers don't know how to report problems.")
		return
	}
	if t, err := time.Parse(time.RFC3339, expires); err == nil && w.config.Now().After(t) {
		w.addWeb("web-security-txt", SeverityWarning, stdSecurityTx, "security.txt has passed its Expires date.")
	}
}
