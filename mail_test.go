package robertparker_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mikecb/robertparker"
)

func (f *fakeDNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	f.mu.Lock()
	f.queries = append(f.queries, name)
	f.mu.Unlock()
	if f.lookupFails[name] {
		return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	var records []*net.MX
	for _, host := range f.mx[name] {
		records = append(records, &net.MX{Host: host})
	}
	if records == nil {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return records, nil
}

func (f *fakeDNS) LookupHost(_ context.Context, name string) ([]string, error) {
	if f.lookupFails[name] {
		return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	if h, ok := f.hosts[name]; ok {
		return h, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeDNS) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if f.lookupFails[addr] {
		return nil, &net.DNSError{Err: "server misbehaving", Name: addr, IsTemporary: true}
	}
	if p, ok := f.ptr[addr]; ok {
		return p, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

func (slowDNS) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (slowDNS) LookupHost(ctx context.Context, name string) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (slowDNS) LookupAddr(ctx context.Context, name string) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// mailDNS is a domain with working mail, for each test to change. It adds no warnings or failures.
func mailDNS() *fakeDNS {
	return &fakeDNS{
		records: map[string][]string{
			"example.com":                      {"v=spf1 mx -all"},
			"_dmarc.example.com":               {goodDMARC},
			"selector1._domainkey.example.com": {"v=DKIM1; k=rsa; p=" + dkimKey(2048)},
			"_smtp._tls.example.com":           {"v=TLSRPTv1; rua=mailto:tls@example.com"},
		},
		mx:    map[string][]string{"example.com": {"mail.example.com."}},
		hosts: map[string][]string{"mail.example.com": {"192.0.2.25"}},
		ptr:   map[string][]string{"192.0.2.25": {"mail.example.com."}},
	}
}

var dkimKeys = map[int]string{}

// dkimKey returns a base64 public key of the given size.
func dkimKey(bits int) string {
	if k, ok := dkimKeys[bits]; ok {
		return k
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	dkimKeys[bits] = base64.StdEncoding.EncodeToString(der)
	return dkimKeys[bits]
}

// mailFindings runs the email checks, and returns every finding other than SPF and DMARC.
func mailFindings(t *testing.T, dns *fakeDNS, client *http.Client) ([]string, *robertparker.Domain) {
	t.Helper()
	d := robertparker.NewDomain("example.com")
	if err := robertparker.EmailAnalyzer(dns, client, nil)(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, f := range summarize(d) {
		_, check, _ := strings.Cut(f, " ")
		if !strings.HasPrefix(check, "spf-") && !strings.HasPrefix(check, "dmarc-") {
			got = append(got, f)
		}
	}
	return got, d
}

func TestMailServers(t *testing.T) {
	missingMTASTS := []string{"info mta-sts"}
	tests := []struct {
		name   string
		change func(*fakeDNS)
		want   []string
	}{
		{"good", func(*fakeDNS) {}, missingMTASTS},
		{"doesn't resolve", func(f *fakeDNS) { delete(f.hosts, "mail.example.com") }, []string{"failure mx-resolve", "info mta-sts"}},
		{"no reverse DNS", func(f *fakeDNS) { delete(f.ptr, "192.0.2.25") }, []string{"info mta-sts", "info mx-reverse-dns"}},
		{"reverse DNS that doesn't confirm", func(f *fakeDNS) { f.ptr["192.0.2.25"] = []string{"elsewhere.example.com."} }, []string{"info mta-sts", "info mx-reverse-dns"}},
		{
			"reverse DNS to another name is fine",
			func(f *fakeDNS) {
				f.ptr["192.0.2.25"] = []string{"out.provider.example."}
				f.hosts["out.provider.example"] = []string{"192.0.2.99", "192.0.2.25"}
			},
			missingMTASTS,
		},
		{"null MX beside a real one", func(f *fakeDNS) { f.mx["example.com"] = []string{".", "mail.example.com."} }, []string{"info mta-sts", "warning mx-null"}},
		{
			"only checks the first few",
			func(f *fakeDNS) {
				f.mx["example.com"] = []string{"a.example.", "b.example.", "c.example.", "d.example.", "broken.example."}
				for _, h := range []string{"a", "b", "c", "d"} {
					f.hosts[h+".example"] = []string{"192.0.2.25"}
				}
			},
			missingMTASTS,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns := mailDNS()
			tt.change(dns)
			if got, _ := mailFindings(t, dns, nil); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParkedDomains(t *testing.T) {
	tests := []struct {
		name  string
		mx    []string
		spf   string
		dmarc string
		want  []string
	}{
		{"done right", []string{"."}, "v=spf1 -all", "v=DMARC1; p=reject; rua=mailto:r@example.com", []string{}},
		{"no null MX", nil, "v=spf1 -all", "v=DMARC1; p=reject; rua=mailto:r@example.com", []string{"info parked-null-mx"}},
		{"soft fail", []string{"."}, "v=spf1 ~all", "v=DMARC1; p=reject; rua=mailto:r@example.com", []string{"warning parked-spf"}},
		{"DMARC monitoring only", []string{"."}, "v=spf1 -all", "v=DMARC1; p=none; rua=mailto:r@example.com", []string{"warning parked-dmarc"}},
		{"DMARC quarantine", []string{"."}, "v=spf1 -all", "v=DMARC1; p=quarantine; rua=mailto:r@example.com", []string{"warning parked-dmarc"}},
		{"sends mail, so not parked", []string{"."}, "v=spf1 include:mail.example.org -all", "v=DMARC1; p=none; rua=mailto:r@example.com", []string{"info dkim-key"}},
		{"ip4 sender", nil, "v=spf1 ip4:192.0.2.1 -all", "v=DMARC1; p=none; rua=mailto:r@example.com", []string{"info dkim-key"}},
		{"denied mechanism isn't a sender", []string{"."}, "v=spf1 -mx -all", "v=DMARC1; p=none; rua=mailto:r@example.com", []string{"warning parked-dmarc"}},
		{"no SPF", []string{"."}, "", "v=DMARC1; p=reject; rua=mailto:r@example.com", []string{}},
		{"no DMARC", []string{"."}, "v=spf1 -all", "", []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns := &fakeDNS{
				records: map[string][]string{"mail.example.org": {"v=spf1 -all"}},
				mx:      map[string][]string{},
			}
			if tt.spf != "" {
				dns.records["example.com"] = []string{tt.spf}
			}
			if tt.dmarc != "" {
				dns.records["_dmarc.example.com"] = []string{tt.dmarc}
			}
			if tt.mx != nil {
				dns.mx["example.com"] = tt.mx
			}
			if got, _ := mailFindings(t, dns, nil); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParkedNeedsEveryAnswer(t *testing.T) {
	// A failed lookup says nothing about being parked, so it must not add parked findings.
	dns := &fakeDNS{
		records: map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=none; rua=mailto:r@example.com"}},
		failing: map[string]bool{"example.com": true},
	}
	d := robertparker.NewDomain("example.com")
	robertparker.EmailAnalyzer(dns, nil, nil)(context.Background(), d)
	for _, f := range d.Findings {
		if strings.HasPrefix(f.Check, "parked-") {
			t.Errorf("got %+v after a failed lookup", f)
		}
	}
}

func TestMailLookupFailures(t *testing.T) {
	for _, name := range []string{"example.com", "mail.example.com"} {
		t.Run(name, func(t *testing.T) {
			dns := mailDNS()
			dns.lookupFails = map[string]bool{name: true}
			d := robertparker.NewDomain("example.com")
			if err := robertparker.EmailAnalyzer(dns, nil, nil)(context.Background(), d); err == nil {
				t.Error("want an error from the failed lookup")
			}
			for _, f := range d.Findings {
				if f.Severity == robertparker.SeverityFailure || f.Severity == robertparker.SeverityWarning {
					t.Errorf("a failed lookup was reported as %+v", f)
				}
			}
			if g := robertparker.Grade(d); g != "" {
				t.Errorf("got grade %q, want none", g)
			}
		})
	}
}

// mtaSTSServer serves a policy at any host, using a certificate for mta-sts.example.com.
func mtaSTSServer(t *testing.T, handler http.HandlerFunc) *http.Client {
	t.Helper()
	ca := newCA(t)
	cert := ca.issue(t, certOptions{names: []string{"mta-sts.example.com"}})
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: ca.pool, Time: func() time.Time { return webNow }},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}}
}

func servePolicy(policy string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/mta-sts.txt" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, policy)
	}
}

func TestMTASTS(t *testing.T) {
	tests := []struct {
		name    string
		records []string
		handler http.HandlerFunc
		want    []string
	}{
		{"none", nil, nil, []string{"info mta-sts"}},
		{"unrelated TXT", []string{"hello"}, nil, []string{"info mta-sts"}},
		{
			"enforced",
			[]string{"v=STSv1; id=1"},
			servePolicy("version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmax_age: 604800\r\n"),
			[]string{},
		},
		{
			"wildcard",
			[]string{"v=STSv1; id=1"},
			servePolicy("version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 604800\n"),
			[]string{},
		},
		{
			"wildcard covers one label",
			[]string{"v=STSv1; id=1"},
			servePolicy("version: STSv1\nmode: enforce\nmx: *.com\nmax_age: 604800\n"),
			[]string{"failure mta-sts-mx"},
		},
		{
			"enforced policy misses a mail server",
			[]string{"v=STSv1; id=1"},
			servePolicy("version: STSv1\nmode: enforce\nmx: other.example.com\nmax_age: 604800\n"),
			[]string{"failure mta-sts-mx"},
		},
		{
			"testing mode",
			[]string{"v=STSv1; id=1"},
			servePolicy("version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 604800\n"),
			[]string{"warning mta-sts"},
		},
		{
			"testing policy misses a mail server",
			[]string{"v=STSv1; id=1"},
			servePolicy("version: STSv1\nmode: testing\nmx: other.example.com\nmax_age: 604800\n"),
			[]string{"warning mta-sts", "warning mta-sts-mx"},
		},
		{"bad version", []string{"v=STSv1; id=1"}, servePolicy("version: STSv2\nmode: enforce\n"), []string{"warning mta-sts"}},
		{"no mode", []string{"v=STSv1; id=1"}, servePolicy("version: STSv1\n"), []string{"warning mta-sts"}},
		{"record without a policy", []string{"v=STSv1; id=1"}, http.NotFound, []string{"warning mta-sts"}},
		{"two records", []string{"v=STSv1; id=1", "v=STSv1; id=2"}, nil, []string{"warning mta-sts"}},
		{
			"redirects aren't followed",
			[]string{"v=STSv1; id=1"},
			func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
			},
			[]string{"warning mta-sts"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns := mailDNS()
			if tt.records != nil {
				dns.records["_mta-sts.example.com"] = tt.records
			}
			var client *http.Client
			if tt.handler != nil {
				client = mtaSTSServer(t, tt.handler)
			}
			if got, _ := mailFindings(t, dns, client); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMTASTSBadCertificate(t *testing.T) {
	dns := mailDNS()
	dns.records["_mta-sts.example.com"] = []string{"v=STSv1; id=1"}
	server := httptest.NewTLSServer(servePolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\n"))
	defer server.Close()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}}
	if got, _ := mailFindings(t, dns, client); !reflect.DeepEqual(got, []string{"warning mta-sts"}) {
		t.Errorf("a policy behind an untrusted certificate doesn't work, got %v", got)
	}
}

func TestMTASTSTimeoutIsUnknown(t *testing.T) {
	dns := mailDNS()
	dns.records["_mta-sts.example.com"] = []string{"v=STSv1; id=1"}
	client := &http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Err: timeoutError{}}
	}}}
	d := robertparker.NewDomain("example.com")
	if err := robertparker.EmailAnalyzer(dns, client, nil)(context.Background(), d); err == nil {
		t.Error("want an error from the timeout")
	}
	if got := summarize(d); !reflect.DeepEqual(got, []string{"unknown mta-sts"}) {
		t.Errorf("got %v", got)
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestTLSRPT(t *testing.T) {
	tests := []struct {
		name    string
		records []string
		want    []string
	}{
		{"none", nil, []string{"info mta-sts", "info tls-rpt"}},
		{"no destination", []string{"v=TLSRPTv1"}, []string{"info mta-sts", "warning tls-rpt"}},
		{"two records", []string{"v=TLSRPTv1; rua=mailto:a@example.com", "v=TLSRPTv1; rua=mailto:b@example.com"}, []string{"info mta-sts", "warning tls-rpt"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns := mailDNS()
			delete(dns.records, "_smtp._tls.example.com")
			if tt.records != nil {
				dns.records["_smtp._tls.example.com"] = tt.records
			}
			if got, _ := mailFindings(t, dns, nil); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDKIM(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want []string
	}{
		{"good", "v=DKIM1; k=rsa; p=" + dkimKey(2048), []string{"info mta-sts"}},
		{"no key type", "v=DKIM1; p=" + dkimKey(2048), []string{"info mta-sts"}},
		{"small key", "v=DKIM1; k=rsa; p=" + dkimKey(1024), []string{"info mta-sts", "warning dkim-key"}},
		{"too small", "v=DKIM1; k=rsa; p=" + smallDKIMKey, []string{"failure dkim-key", "info mta-sts"}},
		{"ed25519", "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=", []string{"info mta-sts"}},
		{"test mode", "v=DKIM1; t=y; p=" + dkimKey(2048), []string{"info dkim-testing", "info mta-sts"}},
		{"SHA-1 only", "v=DKIM1; h=sha1; p=" + dkimKey(2048), []string{"info mta-sts", "warning dkim-hash"}},
		{"unreadable key", "v=DKIM1; p=!!!not base64", []string{"info mta-sts", "warning dkim-key"}},
		{"not a key", "v=DKIM1; p=aGVsbG8=", []string{"info mta-sts", "warning dkim-key"}},
		{"revoked key doesn't count", "v=DKIM1; p=", []string{"info dkim-key", "info mta-sts"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns := mailDNS()
			dns.records["selector1._domainkey.example.com"] = []string{tt.key}
			if got, _ := mailFindings(t, dns, nil); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// smallDKIMKey is a 512-bit RSA public key, smaller than Go will generate, as SubjectPublicKeyInfo.
const smallDKIMKey = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ=="

func TestDKIMMissingIsNotAPenalty(t *testing.T) {
	dns := mailDNS()
	delete(dns.records, "selector1._domainkey.example.com")
	got, d := mailFindings(t, dns, nil)
	if want := []string{"info dkim-key", "info mta-sts"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if g := robertparker.Grade(d); g != "A" {
		t.Errorf("got grade %q: not finding a key can't count against a domain", g)
	}
}

func TestDKIMLookupFailureIsNotAFinding(t *testing.T) {
	dns := mailDNS()
	dns.failing = map[string]bool{"default._domainkey.example.com": true}
	got, d := mailFindings(t, dns, nil)
	if want := []string{"info mta-sts"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if g := robertparker.Grade(d); g != "A" {
		t.Errorf("got grade %q", g)
	}
}

func TestMissingNewProtectionsDontCostAnything(t *testing.T) {
	_, d := mailFindings(t, mailDNS(), nil)
	if g := robertparker.Grade(d); g != "A" {
		t.Errorf("got grade %q without MTA-STS, want A: %+v", g, d.Findings)
	}
}

func TestReverseDNSFailureDoesNotBlockTheGrade(t *testing.T) {
	dns := mailDNS()
	dns.lookupFails = map[string]bool{"192.0.2.25": true}
	got, d := mailFindings(t, dns, nil)
	if want := []string{"info mta-sts", "info mx-reverse-dns"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if g := robertparker.Grade(d); g != "A" {
		t.Errorf("got grade %q: an information check can't stop a domain being graded", g)
	}
}
