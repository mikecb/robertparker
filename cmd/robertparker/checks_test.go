package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeResolver answers from a map, and fails for the names in failing.
type fakeResolver struct {
	records map[string][]string
	mx      map[string]string
	failing map[string]bool
	calls   atomic.Int64
}

func (f *fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if host, ok := f.mx[name]; ok {
		return []*net.MX{{Host: host}}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeResolver) LookupHost(_ context.Context, name string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.calls.Add(1)
	if f.failing[name] {
		return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	if r, ok := f.records[name]; ok {
		return r, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// useResolver replaces the resolver for one test.
func useResolver(t *testing.T, f *fakeResolver) {
	t.Helper()
	old := resolver
	resolver = f
	t.Cleanup(func() { resolver = old })
}

func goodResolver() *fakeResolver {
	return &fakeResolver{
		records: map[string][]string{
			"good.com":        {"v=spf1 -all"},
			"_dmarc.good.com": {"v=DMARC1; p=reject; rua=mailto:r@good.com"},
			"weak.com":        {"v=spf1 ip4:192.0.2.1 ~all"},
			"_dmarc.weak.com": {"v=DMARC1; p=none; rua=mailto:r@weak.com"},
		},
		mx: map[string]string{"good.com": "."},
	}
}

func TestChecksJSON(t *testing.T) {
	useResolver(t, goodResolver())
	code, out, errOut := runCLI(t, "", "-checks", "email", "good.com", "weak.com", "bare.com")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	got := decode(t, out)
	if len(got) != 3 {
		t.Fatalf("got %d results", len(got))
	}
	if got[0].Grade != "A" || len(got[0].Findings) != 0 {
		t.Errorf("good.com: %+v", got[0])
	}
	if got[1].Grade != "B" || len(got[1].Findings) != 2 || got[1].Findings[0].Check != "dmarc-policy" {
		t.Errorf("weak.com: %+v", got[1])
	}
	if got[2].Grade != "F" || len(got[2].Findings) != 3 {
		t.Errorf("bare.com: %+v", got[2])
	}
}

func TestChecksText(t *testing.T) {
	useResolver(t, goodResolver())
	code, out, _ := runCLI(t, "", "-checks", "email", "-o", "text", "good.com", "weak.com")
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	rows := strings.Split(strings.TrimSpace(out), "\n")
	if len(rows) != 4 {
		t.Fatalf("want a header and 3 rows, got:\n%s", out)
	}
	if f := strings.Fields(rows[0]); strings.Join(f, " ") != "DOMAIN GRADE AREAS SEVERITY CHECK MESSAGE" {
		t.Errorf("unexpected header %q", rows[0])
	}
	if f := strings.Fields(rows[1]); strings.Join(f, " ") != "good.com A email=A - - -" {
		t.Errorf("unexpected row %q", rows[1])
	}
	if f := strings.Fields(rows[2]); len(f) < 6 || f[0] != "weak.com" || f[1] != "B" || f[2] != "email=B" || f[3] != "warning" || f[4] != "dmarc-policy" {
		t.Errorf("unexpected row %q", rows[2])
	}
}

func TestChecksFailedLookup(t *testing.T) {
	f := goodResolver()
	f.failing = map[string]bool{"good.com": true}
	useResolver(t, f)
	code, out, errOut := runCLI(t, "", "-checks", "email", "good.com", "weak.com")
	if code != 1 || !strings.Contains(errOut, "good.com") || !strings.Contains(errOut, "server misbehaving") {
		t.Errorf("got exit %d, stderr %q, want 1 and the lookup error", code, errOut)
	}
	got := decode(t, out)
	if len(got) != 2 || got[0].Grade != "" || got[1].Grade != "B" {
		t.Errorf("want no grade for good.com, and weak.com still graded, got %+v", got)
	}
}

func TestChecksWithPermute(t *testing.T) {
	useResolver(t, goodResolver())
	code, out, _ := runCLI(t, "", "-checks", "email", "-permute", "good.com")
	got := decode(t, out)
	if code != 0 || len(got) != 1 || got[0].Grade != "A" || len(got[0].Permutations) == 0 {
		t.Errorf("exit %d: %+v", code, got)
	}
	if code, _, errOut := runCLI(t, "", "-checks", "email", "-permute", "-o", "text", "good.com"); code != 2 || !strings.Contains(errOut, "not both") {
		t.Errorf("got exit %d, stderr %q", code, errOut)
	}
}

func TestChecksOffByDefault(t *testing.T) {
	f := goodResolver()
	useResolver(t, f)
	code, out, _ := runCLI(t, "", "good.com")
	if code != 0 || f.calls.Load() != 0 || strings.Contains(out, "Findings") || strings.Contains(out, "Grade") {
		t.Errorf("exit %d, %d lookups, output %s", code, f.calls.Load(), out)
	}
}

func TestChecksFlags(t *testing.T) {
	useResolver(t, goodResolver())
	if code, _, errOut := runCLI(t, "", "-checks", "nonsense", "good.com"); code != 2 || !strings.Contains(errOut, `unknown check "nonsense"`) {
		t.Errorf("got exit %d, stderr %q", code, errOut)
	}
	if code, out, _ := runCLI(t, "", "-checks", "email", "-workers", "1", "-rate", "0", "-timeout", "1s", "good.com"); code != 0 || decode(t, out)[0].Grade != "A" {
		t.Errorf("got exit %d, output %s", code, out)
	}
}

func TestNewResolver(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	addr := listener.Addr().String()

	// The address passed to Dial is the system's server, which must be ignored.
	conn, err := newResolver(addr).Dial(context.Background(), "tcp", "192.0.2.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := conn.RemoteAddr().String(); got != addr {
		t.Errorf("dialed %s, want %s", got, addr)
	}
}

// Grade and Findings stay out of JSON when no checks ran, so output for existing uses doesn't change.
func TestNoChecksKeepsOutput(t *testing.T) {
	_, out, _ := runCLI(t, "", "example.com")
	want := `{"FQDN":"example.com","Suffix":"com","Secondary":"example","ICANN":true,"Entropy":2.5216406363433186,"Permutations":null}`
	if strings.TrimSpace(out) != want {
		t.Errorf("got %s, want %s", out, want)
	}
}

// useSite sends the -checks tls and web requests to a local HTTPS server, whose certificate won't verify.
func useSite(t *testing.T) {
	t.Helper()
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	}))
	t.Cleanup(site.Close)
	old := webDial
	webDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, site.Listener.Addr().String())
	}
	t.Cleanup(func() { webDial = old })
}

func TestChecksWeb(t *testing.T) {
	useSite(t)
	useResolver(t, goodResolver())
	code, out, errOut := runCLI(t, "", "-checks", "email,tls,web", "good.com")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	got := decode(t, out)
	if len(got) != 1 || got[0].Grades["email"] != "A" || got[0].Grades["tls"] == "" || got[0].Grades["web"] == "" {
		t.Fatalf("want a grade for each area, got %+v", got)
	}
	if got[0].Grade == "A" {
		t.Errorf("the overall grade should reflect the untrusted certificate: %+v", got[0])
	}
}

func TestChecksTLSProbe(t *testing.T) {
	useSite(t)
	code, out, errOut := runCLI(t, "", "-checks", "tls-probe", "good.com")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	got := decode(t, out)
	if len(got) != 1 || got[0].Grades["tls"] == "" {
		t.Fatalf("tls-probe should grade tls, got %+v", got)
	}
	if got[0].Grades["web"] != "" {
		t.Errorf("tls-probe shouldn't grade web: %+v", got[0])
	}
}

func TestChecksChooseAreas(t *testing.T) {
	useSite(t)
	f := goodResolver()
	useResolver(t, f)
	code, out, _ := runCLI(t, "", "-checks", "tls", "good.com")
	got := decode(t, out)
	if code != 0 || len(got) != 1 || len(got[0].Grades) != 1 || got[0].Grades["tls"] == "" {
		t.Errorf("exit %d: %+v", code, got)
	}
	if f.calls.Load() != 0 {
		t.Errorf("-checks tls made %d email lookups", f.calls.Load())
	}
}

func TestChecksTextShowsAreas(t *testing.T) {
	useSite(t)
	useResolver(t, goodResolver())
	_, out, _ := runCLI(t, "", "-checks", "email,tls", "-o", "text", "good.com")
	if !strings.Contains(out, "email=A,tls=") {
		t.Errorf("want the area grades in sorted order, got:\n%s", out)
	}
}

// fakeLookalikes answers lookups for a few names.
type fakeLookalikes struct {
	hosts map[string][]string
	mx    map[string]string
	fail  bool
}

func (f *fakeLookalikes) LookupHost(_ context.Context, name string) ([]string, error) {
	if f.fail {
		return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	if h, ok := f.hosts[name]; ok {
		return append([]string{}, h...), nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeLookalikes) LookupNS(_ context.Context, name string) ([]*net.NS, error) {
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeLookalikes) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if host, ok := f.mx[name]; ok {
		return []*net.MX{{Host: host}}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func useLookalikes(t *testing.T, f *fakeLookalikes) {
	t.Helper()
	old := lookalikes
	lookalikes = f
	t.Cleanup(func() { lookalikes = old })
}

func goodLookalikes() *fakeLookalikes {
	return &fakeLookalikes{
		hosts: map[string][]string{"exmaple.com": {"192.0.2.1"}, "example.net": {"192.0.2.2"}},
		mx:    map[string]string{"exmaple.com": "mail.exmaple.com."},
	}
}

func TestLookupJSON(t *testing.T) {
	useLookalikes(t, goodLookalikes())
	code, out, errOut := runCLI(t, "", "-rate", "0", "-lookup", "example.com")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	got := decode(t, out)
	if len(got) != 1 || len(got[0].Lookalikes) != 2 || got[0].Lookalikes[0].ASCII != "exmaple.com" || len(got[0].Lookalikes[0].MailServers) != 1 {
		t.Fatalf("%+v", got)
	}
	if got[0].Permutations != nil {
		t.Errorf("-lookup alone shouldn't list every permutation, got %d", len(got[0].Permutations))
	}
}

func TestLookupWithPermute(t *testing.T) {
	useLookalikes(t, goodLookalikes())
	_, out, _ := runCLI(t, "", "-rate", "0", "-lookup", "-permute", "example.com")
	if got := decode(t, out); len(got) != 1 || len(got[0].Lookalikes) != 2 || len(got[0].Permutations) < 100 {
		t.Errorf("want both lists, got %d and %d", len(got[0].Lookalikes), len(got[0].Permutations))
	}
}

func TestLookupText(t *testing.T) {
	useLookalikes(t, goodLookalikes())
	code, out, _ := runCLI(t, "", "-rate", "0", "-lookup", "-o", "text", "example.com")
	rows := strings.Split(strings.TrimSpace(out), "\n")
	if code != 0 || len(rows) != 3 {
		t.Fatalf("exit %d, want a header and 2 rows:\n%s", code, out)
	}
	if f := strings.Fields(rows[0]); strings.Join(f, " ") != "DOMAIN FUZZER LOOKALIKE ASCII MAIL SHARED-NS BROKEN-DNS ADDRESSES" {
		t.Errorf("unexpected header %q", rows[0])
	}
	if f := strings.Fields(rows[1]); strings.Join(f, " ") != "example.com transposition exmaple.com exmaple.com yes - - 192.0.2.1" {
		t.Errorf("unexpected row %q", rows[1])
	}
	if f := strings.Fields(rows[2]); strings.Join(f, " ") != "example.com tld-swap example.net example.net - - - 192.0.2.2" {
		t.Errorf("unexpected row %q", rows[2])
	}
}

func TestLookupFailure(t *testing.T) {
	useLookalikes(t, &fakeLookalikes{fail: true})
	code, out, errOut := runCLI(t, "", "-rate", "0", "-lookup", "example.com")
	got := decode(t, out)
	if code != 1 || !strings.Contains(errOut, "lookalike lookups failed") || len(got) != 1 || got[0].LookupFailures == 0 {
		t.Errorf("got exit %d, stderr %q, %+v", code, errOut, got)
	}
}

func TestLookupWithChecks(t *testing.T) {
	useLookalikes(t, goodLookalikes())
	useResolver(t, goodResolver())
	code, out, _ := runCLI(t, "", "-rate", "0", "-lookup", "-checks", "email", "good.com")
	if got := decode(t, out); code != 0 || len(got) != 1 || got[0].Grade != "A" {
		t.Errorf("exit %d: %+v", code, got)
	}
	if code, _, errOut := runCLI(t, "", "-rate", "0", "-lookup", "-checks", "email", "-o", "text", "good.com"); code != 2 || !strings.Contains(errOut, "not both") {
		t.Errorf("got exit %d, stderr %q", code, errOut)
	}
}

func TestLookupOffByDefault(t *testing.T) {
	useLookalikes(t, goodLookalikes())
	if _, out, _ := runCLI(t, "", "example.com"); strings.Contains(out, "Lookalikes") {
		t.Errorf("got %s", out)
	}
}
