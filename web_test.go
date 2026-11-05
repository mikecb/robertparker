package robertparker_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mikecb/robertparker"
)

var webNow = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

// testCA signs certificates for the tests.
type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
	pool *x509.CertPool
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             webNow.AddDate(-5, 0, 0),
		NotAfter:              webNow.AddDate(5, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert, key, pool}
}

// certOptions describes a leaf certificate. The zero value is a good one.
type certOptions struct {
	names     []string
	notBefore time.Time
	notAfter  time.Time
	key       crypto.Signer
	noSCT     bool
}

// issue makes a leaf certificate.
func (ca *testCA) issue(t *testing.T, o certOptions) tls.Certificate {
	t.Helper()
	if o.names == nil {
		o.names = []string{"example.com", "www.example.com"}
	}
	if o.notBefore.IsZero() {
		o.notBefore = webNow.AddDate(0, 0, -30)
	}
	if o.notAfter.IsZero() {
		o.notAfter = o.notBefore.AddDate(0, 0, 90)
	}
	if o.key == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		o.key = key
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: o.names[0]},
		DNSNames:     o.names,
		NotBefore:    o.notBefore,
		NotAfter:     o.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if !o.noSCT {
		sct := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
		template.ExtraExtensions = []pkix.Extension{{Id: sct, Value: []byte{4, 2, 0, 0}}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, o.key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: o.key}
}

var goodHeaders = map[string]string{
	"Strict-Transport-Security":  "max-age=63072000; includeSubDomains; preload",
	"Content-Security-Policy":    "default-src 'self'; frame-ancestors 'none'",
	"X-Content-Type-Options":     "nosniff",
	"Permissions-Policy":         "camera=()",
	"Cross-Origin-Opener-Policy": "same-origin",
}

// testSite is a site for the checks to request. Its zero value is a good site.
type testSite struct {
	cert      *tls.Certificate
	tlsConfig func(*tls.Config)
	handler   http.HandlerFunc  //Replaces the page.
	headers   map[string]string //Replaces or, with an empty value, removes headers from goodHeaders.
	plain     http.HandlerFunc  //Replaces the HTTP redirect.
	security  string            //Replaces security.txt.
	noPlain   bool              //Nothing listens on port 80.
	noHTTPS   bool              //Nothing listens on port 443.
	down      map[string]bool   //Hosts that don't exist.
	dialErr   error             //Every dial fails with this.
}

// start runs the site, and returns a config that sends requests to it.
func (s testSite) start(t *testing.T, ca *testCA) robertparker.WebConfig {
	t.Helper()
	security := s.security
	if security == "" {
		security = "Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z\n"
	}
	page := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/security.txt" {
			w.Write([]byte(security))
			return
		}
		for name, value := range goodHeaders {
			if _, replaced := s.headers[name]; !replaced {
				w.Header().Set(name, value)
			}
		}
		for name, value := range s.headers {
			if value != "" {
				w.Header().Set(name, value)
			}
		}
		if s.handler != nil {
			s.handler(w, r)
		}
	}
	secure := httptest.NewUnstartedServer(http.HandlerFunc(page))
	cert := s.cert
	if cert == nil {
		c := ca.issue(t, certOptions{})
		cert = &c
	}
	secure.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
	if s.tlsConfig != nil {
		s.tlsConfig(secure.TLS)
	}
	secure.StartTLS()
	t.Cleanup(secure.Close)

	redirect := s.plain
	if redirect == nil {
		redirect = func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+"/", http.StatusMovedPermanently)
		}
	}
	plain := httptest.NewServer(redirect)
	t.Cleanup(plain.Close)

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if s.dialErr != nil {
			return nil, s.dialErr
		}
		host, port, _ := net.SplitHostPort(addr)
		refused := &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
		if s.down[host] {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		target := secure.Listener.Addr().String()
		if port == "80" {
			target = plain.Listener.Addr().String()
			if s.noPlain {
				return nil, refused
			}
		} else if s.noHTTPS {
			return nil, refused
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}
	return robertparker.WebConfig{TLS: true, Web: true, DialContext: dial, Roots: ca.pool, Now: func() time.Time { return webNow }}
}

// checkSite runs the checks on a site at example.com.
func checkSite(t *testing.T, ca *testCA, s testSite) (*robertparker.Domain, error) {
	t.Helper()
	d := robertparker.NewDomain("example.com")
	err := robertparker.WebAnalyzer(s.start(t, ca), nil)(context.Background(), d)
	robertparker.Grade(d)
	return d, err
}

func TestWebChecks(t *testing.T) {
	ca := newCA(t)
	issue := func(o certOptions) *tls.Certificate {
		c := ca.issue(t, o)
		return &c
	}
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		site testSite
		want []string
	}{
		{"good site", testSite{}, []string{}},

		{"expired", testSite{cert: issue(certOptions{notBefore: webNow.AddDate(0, 0, -100), notAfter: webNow.AddDate(0, 0, -10)})}, []string{"failure tls-expiry"}},
		{"not yet valid", testSite{cert: issue(certOptions{notBefore: webNow.AddDate(0, 0, 5)})}, []string{"failure tls-expiry"}},
		{"expiring soon", testSite{cert: issue(certOptions{notBefore: webNow.AddDate(0, 0, -85)})}, []string{"warning tls-expiry"}},
		{"wrong name", testSite{cert: issue(certOptions{names: []string{"other.example.org"}})}, []string{"failure tls-hostname"}},
		{"untrusted", testSite{cert: func() *tls.Certificate { c := newCA(t).issue(t, certOptions{}); return &c }()}, []string{"failure tls-chain"}},
		{
			"public rules skip a private certificate",
			testSite{cert: func() *tls.Certificate {
				c := newCA(t).issue(t, certOptions{notBefore: webNow.AddDate(-1, 0, 0), notAfter: webNow.AddDate(1, 0, 0), noSCT: true})
				return &c
			}()},
			[]string{"failure tls-chain"},
		},
		{"at the lifetime limit", testSite{cert: issue(certOptions{notBefore: webNow.AddDate(0, 0, -30), notAfter: webNow.AddDate(0, 0, 170)})}, []string{}},
		{"over the lifetime limit", testSite{cert: issue(certOptions{notBefore: webNow.AddDate(0, 0, -30), notAfter: webNow.AddDate(0, 0, 171)})}, []string{"failure tls-lifetime"}},
		{"old rules for old certificates", testSite{cert: issue(certOptions{notBefore: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), notAfter: time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)})}, []string{}},
		{"weak key", testSite{cert: issue(certOptions{key: rsa1024})}, []string{"failure tls-key"}},
		{"no transparency", testSite{cert: issue(certOptions{noSCT: true})}, []string{"warning tls-transparency"}},
		{
			"TLS 1.2",
			testSite{tlsConfig: func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 }},
			[]string{"info tls-version", "warning tls-post-quantum"},
		},
		{
			"TLS 1.0",
			testSite{tlsConfig: func(c *tls.Config) { c.MinVersion, c.MaxVersion = tls.VersionTLS10, tls.VersionTLS10 }},
			[]string{"failure tls-version", "warning tls-cipher", "warning tls-post-quantum"},
		},
		{
			"no post-quantum",
			testSite{tlsConfig: func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.X25519} }},
			[]string{"warning tls-post-quantum"},
		},

		{"no redirect", testSite{plain: func(http.ResponseWriter, *http.Request) {}}, []string{"warning web-https-redirect"}},
		{"no port 80", testSite{noPlain: true}, []string{}},
		{
			"redirect by way of www",
			testSite{plain: func(w http.ResponseWriter, r *http.Request) {
				target := "https://www.example.com/"
				if r.Host == "example.com" {
					target = "http://www.example.com/"
				}
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			}},
			[]string{},
		},
		{
			"HSTS only after the redirect to www",
			testSite{headers: map[string]string{"Strict-Transport-Security": ""}, handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Host == "example.com" {
					http.Redirect(w, r, "https://www.example.com/", http.StatusMovedPermanently)
					return
				}
				w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			}},
			[]string{},
		},
		{
			"HTTPS redirects to HTTP",
			testSite{handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Scheme == "" && r.TLS != nil {
					http.Redirect(w, r, "http://example.com/plain", http.StatusFound)
				}
			}, plain: func(http.ResponseWriter, *http.Request) {}},
			[]string{"failure web-https-redirect", "info web-coop", "info web-permissions", "info web-security-txt", "warning web-csp", "warning web-framing", "warning web-https-redirect", "warning web-nosniff"},
		},
		{"no HSTS", testSite{headers: map[string]string{"Strict-Transport-Security": ""}}, []string{"warning web-hsts"}},
		{"short HSTS", testSite{headers: map[string]string{"Strict-Transport-Security": "max-age=3600; includeSubDomains; preload"}}, []string{"warning web-hsts"}},
		{"HSTS without subdomains", testSite{headers: map[string]string{"Strict-Transport-Security": "max-age=31536000"}}, []string{"info web-hsts"}},
		{"HSTS without preload", testSite{headers: map[string]string{"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}}, []string{"info web-hsts"}},
		{"no CSP", testSite{headers: map[string]string{"Content-Security-Policy": ""}}, []string{"warning web-csp", "warning web-framing"}},
		{
			"report-only CSP",
			testSite{headers: map[string]string{"Content-Security-Policy": "", "Content-Security-Policy-Report-Only": "default-src 'self'", "X-Frame-Options": "DENY"}},
			[]string{"warning web-csp"},
		},
		{"unsafe-inline", testSite{headers: map[string]string{"Content-Security-Policy": "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"}}, []string{"warning web-csp"}},
		{"unsafe-inline with a nonce", testSite{headers: map[string]string{"Content-Security-Policy": "script-src 'nonce-abc' 'unsafe-inline'; frame-ancestors 'none'"}}, []string{}},
		{"unsafe-eval", testSite{headers: map[string]string{"Content-Security-Policy": "script-src 'unsafe-eval'; frame-ancestors 'none'"}}, []string{"warning web-csp"}},
		{"wildcard", testSite{headers: map[string]string{"Content-Security-Policy": "default-src *; frame-ancestors 'none'"}}, []string{"warning web-csp"}},
		{"img wildcard is fine", testSite{headers: map[string]string{"Content-Security-Policy": "default-src 'self'; img-src *; frame-ancestors 'none'"}}, []string{}},
		{"framing by header", testSite{headers: map[string]string{"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "SAMEORIGIN"}}, []string{}},
		{"no framing protection", testSite{headers: map[string]string{"Content-Security-Policy": "default-src 'self'"}}, []string{"warning web-framing"}},
		{"no nosniff", testSite{headers: map[string]string{"X-Content-Type-Options": ""}}, []string{"warning web-nosniff"}},
		{"leaky referrer", testSite{headers: map[string]string{"Referrer-Policy": "unsafe-url"}}, []string{"warning web-referrer"}},
		{"strict referrer", testSite{headers: map[string]string{"Referrer-Policy": "strict-origin-when-cross-origin"}}, []string{}},
		{"no permissions policy", testSite{headers: map[string]string{"Permissions-Policy": ""}}, []string{"info web-permissions"}},
		{"no COOP", testSite{headers: map[string]string{"Cross-Origin-Opener-Policy": ""}}, []string{"info web-coop"}},
		{"obsolete headers", testSite{headers: map[string]string{"Expect-CT": "max-age=1", "Public-Key-Pins": "x", "X-XSS-Protection": "1; mode=block"}}, []string{"info web-obsolete", "info web-obsolete", "info web-obsolete"}},
		{"XSS protection off", testSite{headers: map[string]string{"X-XSS-Protection": "0"}}, []string{}},
		{"server version", testSite{headers: map[string]string{"Server": "nginx/1.25.3"}}, []string{"info web-disclosure"}},
		{"server name only", testSite{headers: map[string]string{"Server": "nginx"}}, []string{}},
		{"powered by", testSite{headers: map[string]string{"X-Powered-By": "PHP"}}, []string{"info web-disclosure"}},
		{
			"reflected CORS",
			testSite{handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}},
			[]string{"failure web-cors"},
		},
		{"wildcard CORS with credentials", testSite{headers: map[string]string{"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}}, []string{"warning web-cors"}},
		{"wildcard CORS", testSite{headers: map[string]string{"Access-Control-Allow-Origin": "*"}}, []string{}},
		{
			"bare cookie",
			testSite{handler: func(w http.ResponseWriter, r *http.Request) {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "x"})
			}},
			[]string{"info web-cookies", "info web-cookies", "warning web-cookies"},
		},
		{
			"good cookie",
			testSite{handler: func(w http.ResponseWriter, r *http.Request) {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "x", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			}},
			[]string{},
		},
		{"no security.txt", testSite{security: "not here"}, []string{"info web-security-txt"}},
		{"expired security.txt", testSite{security: "Contact: mailto:a@example.com\nExpires: 2020-01-01T00:00:00Z\n"}, []string{"warning web-security-txt"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := checkSite(t, ca, tt.site)
			if err != nil {
				t.Fatal(err)
			}
			if got := summarize(d); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v\n%+v", got, tt.want, d.Findings)
			}
		})
	}
}

func TestWebAreasGrade(t *testing.T) {
	ca := newCA(t)
	expired := ca.issue(t, certOptions{notBefore: webNow.AddDate(0, 0, -100), notAfter: webNow.AddDate(0, 0, -10)})
	d, err := checkSite(t, ca, testSite{cert: &expired})
	if err != nil {
		t.Fatal(err)
	}
	if d.Grades["tls"] != "D" || d.Grades["web"] != "A" || d.Grade != "D" {
		t.Errorf("want tls D, web A, and D overall, got %v, %s", d.Grades, d.Grade)
	}
}

func TestWebChooseAreas(t *testing.T) {
	ca := newCA(t)
	expired := ca.issue(t, certOptions{notBefore: webNow.AddDate(0, 0, -100), notAfter: webNow.AddDate(0, 0, -10)})
	config := testSite{cert: &expired, headers: map[string]string{"X-Content-Type-Options": ""}}.start(t, ca)

	config.Web = false
	d := robertparker.NewDomain("example.com")
	robertparker.WebAnalyzer(config, nil)(context.Background(), d)
	robertparker.Grade(d)
	if got := summarize(d); !reflect.DeepEqual(got, []string{"failure tls-expiry"}) || len(d.Grades) != 1 {
		t.Errorf("TLS only: got %v, grades %v", got, d.Grades)
	}

	config.Web, config.TLS = true, false
	d = robertparker.NewDomain("example.com")
	robertparker.WebAnalyzer(config, nil)(context.Background(), d)
	robertparker.Grade(d)
	if got := summarize(d); !reflect.DeepEqual(got, []string{"warning web-nosniff"}) || len(d.Grades) != 1 {
		t.Errorf("Web only: got %v, grades %v", got, d.Grades)
	}
}

func TestWebFallsBackToWWW(t *testing.T) {
	ca := newCA(t)
	d, err := checkSite(t, ca, testSite{down: map[string]bool{"example.com": true}})
	if err != nil {
		t.Fatal(err)
	}
	if got := summarize(d); len(got) != 0 || d.Grade != "A" {
		t.Errorf("got %v, grade %q, want www.example.com to be checked", got, d.Grade)
	}
}

func TestWebNoHTTPS(t *testing.T) {
	d, err := checkSite(t, newCA(t), testSite{noHTTPS: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"failure tls-https", "failure web-https"}
	if got := summarize(d); !reflect.DeepEqual(got, want) || d.Grades["tls"] != "D" || d.Grades["web"] != "D" {
		t.Errorf("got %v, grades %v, want %v", got, d.Grades, want)
	}
}

func TestWebNoSiteIsNotGraded(t *testing.T) {
	d, err := checkSite(t, newCA(t), testSite{noHTTPS: true, noPlain: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"info tls-site", "info web-site"}
	if got := summarize(d); !reflect.DeepEqual(got, want) || d.Grade != "" || len(d.Grades) != 0 {
		t.Errorf("got %v, grade %q, grades %v", got, d.Grade, d.Grades)
	}
}

func TestWebHandshakeFailure(t *testing.T) {
	// Something that isn't TLS listens on port 443: first plain HTTP, then bytes that aren't any protocol.
	garbage, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer garbage.Close()
	go func() {
		for {
			conn, err := garbage.Accept()
			if err != nil {
				return
			}
			conn.Read(make([]byte, 4096)) // Read the hello first, or closing resets the connection.
			conn.Write([]byte(strings.Repeat("not tls ", 100)))
			conn.Close()
		}
	}()

	base := testSite{}.start(t, newCA(t))
	base.Web = false
	httpOnPort443 := base
	httpOnPort443.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		return base.DialContext(ctx, network, net.JoinHostPort(host, "80"))
	}
	garbageOnPort443 := base
	garbageOnPort443.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, garbage.Addr().String())
	}

	for _, config := range []robertparker.WebConfig{httpOnPort443, garbageOnPort443} {
		d := robertparker.NewDomain("example.com")
		if err := robertparker.WebAnalyzer(config, nil)(context.Background(), d); err != nil {
			t.Fatal(err)
		}
		if got := summarize(d); !reflect.DeepEqual(got, []string{"failure tls-handshake"}) {
			t.Errorf("got %v: %+v", got, d.Findings)
		}
	}
}

func TestWebRequestFailureIsNotAFinding(t *testing.T) {
	d, err := checkSite(t, newCA(t), testSite{dialErr: context.DeadlineExceeded})
	if err == nil {
		t.Error("want an error from the failed request")
	}
	want := []string{"unknown tls-request", "unknown web-request"}
	if got := summarize(d); !reflect.DeepEqual(got, want) || d.Grade != "" || len(d.Grades) != 0 {
		t.Errorf("got %v, grade %q, grades %v, want no grades", got, d.Grade, d.Grades)
	}
}

func TestWebIdentifiesItself(t *testing.T) {
	var agent, origin string
	ca := newCA(t)
	s := testSite{handler: func(w http.ResponseWriter, r *http.Request) {
		agent, origin = r.UserAgent(), r.Header.Get("Origin")
	}}
	if _, err := checkSite(t, ca, s); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(agent, "robertparker ") || !strings.HasSuffix(origin, ".invalid") {
		t.Errorf("got User-Agent %q, Origin %q", agent, origin)
	}
}

func TestWebRedirectLimit(t *testing.T) {
	requests := 0
	s := testSite{handler: func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Redirect(w, r, "/again", http.StatusFound)
	}}
	if _, err := checkSite(t, newCA(t), s); err != nil {
		t.Fatal(err)
	}
	if requests > 8 {
		t.Errorf("followed %d redirects from a loop", requests)
	}
}

func TestWebSkipsBareSuffix(t *testing.T) {
	d := robertparker.NewDomain("com")
	config := robertparker.WebConfig{TLS: true, Web: true, DialContext: func(context.Context, string, string) (net.Conn, error) {
		t.Error("a bare suffix was requested")
		return nil, errors.New("no")
	}}
	if err := robertparker.WebAnalyzer(config, nil)(context.Background(), d); err != nil || len(d.Findings) != 0 {
		t.Errorf("got %v, %+v", err, d.Findings)
	}
}

func TestGradeWorstAreaWins(t *testing.T) {
	d := robertparker.NewDomain("example.com")
	d.Checked("a")
	d.Checked("b")
	d.Checked("a")
	d.Findings = []robertparker.Finding{{Area: "b", Severity: robertparker.SeverityFailure}}
	if g := robertparker.Grade(d); g != "D" || d.Grades["a"] != "A" || d.Grades["b"] != "D" || len(d.Grades) != 2 {
		t.Errorf("got %q, %v", g, d.Grades)
	}
	d.Findings = append(d.Findings, robertparker.Finding{Area: "a", Severity: robertparker.SeverityUnknown})
	if g := robertparker.Grade(d); g != "" || d.Grades["b"] != "D" || len(d.Grades) != 1 {
		t.Errorf("an unknown in one area: got %q, %v, want no overall grade, but b still graded", g, d.Grades)
	}
}

func TestGradeNothingChecked(t *testing.T) {
	if g := robertparker.Grade(robertparker.NewDomain("example.com")); g != "" {
		t.Errorf("got grade %q with nothing checked, want none", g)
	}
}

func TestWebChecksTheHostGiven(t *testing.T) {
	ca := newCA(t)
	var hosts []string
	cert := ca.issue(t, certOptions{names: []string{"api.example.com"}})
	s := testSite{cert: &cert, handler: func(w http.ResponseWriter, r *http.Request) { hosts = append(hosts, r.Host) }}
	d := robertparker.NewDomain("api.example.com")
	if err := robertparker.WebAnalyzer(s.start(t, ca), nil)(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if got := summarize(d); len(got) != 0 {
		t.Errorf("got %v: the certificate is only valid for the host given", got)
	}
	if len(hosts) == 0 || !strings.HasPrefix(hosts[0], "api.example.com") {
		t.Errorf("requested %v", hosts)
	}
}

func TestWebSubdomainDoesNotFallBackToWWW(t *testing.T) {
	ca := newCA(t)
	s := testSite{down: map[string]bool{"api.example.com": true}}
	d := robertparker.NewDomain("api.example.com")
	if err := robertparker.WebAnalyzer(s.start(t, ca), nil)(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	want := []string{"info tls-site", "info web-site"}
	if got := summarize(d); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestGradeCountsEachCheckOnce(t *testing.T) {
	d := robertparker.NewDomain("example.com")
	d.Checked("x")
	for i := 0; i < 5; i++ {
		d.Findings = append(d.Findings, robertparker.Finding{Area: "x", Check: "same", Severity: robertparker.SeverityWarning})
	}
	if g := robertparker.Grade(d); g != "B" {
		t.Errorf("got %q for one check found five ways, want B", g)
	}
	d.Findings = append(d.Findings, robertparker.Finding{Area: "x", Check: "same", Severity: robertparker.SeverityFailure})
	if g := robertparker.Grade(d); g != "D" {
		t.Errorf("got %q, want the check's worst finding to count", g)
	}
}

func TestGradeWebWarningsCostLess(t *testing.T) {
	d := robertparker.NewDomain("example.com")
	d.Checked(robertparker.AreaWeb)
	for _, check := range []string{"a", "b", "c"} {
		d.Findings = append(d.Findings, robertparker.Finding{Area: robertparker.AreaWeb, Check: check, Severity: robertparker.SeverityWarning})
	}
	if g := robertparker.Grade(d); g != "C" {
		t.Errorf("got %q for three web warnings, want C", g)
	}
}
