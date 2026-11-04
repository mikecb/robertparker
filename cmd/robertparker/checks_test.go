package main

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeResolver answers from a map, and fails for the names in failing.
type fakeResolver struct {
	records map[string][]string
	failing map[string]bool
	calls   atomic.Int64
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
	return &fakeResolver{records: map[string][]string{
		"good.com":        {"v=spf1 -all"},
		"_dmarc.good.com": {"v=DMARC1; p=reject; rua=mailto:r@good.com"},
		"weak.com":        {"v=spf1 ~all"},
		"_dmarc.weak.com": {"v=DMARC1; p=none; rua=mailto:r@weak.com"},
	}}
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
	if got[1].Grade != "B" || len(got[1].Findings) != 1 || got[1].Findings[0].Check != "dmarc-policy" {
		t.Errorf("weak.com: %+v", got[1])
	}
	if got[2].Grade != "F" || len(got[2].Findings) != 2 {
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
	if len(rows) != 3 {
		t.Fatalf("want a header and 2 rows, got:\n%s", out)
	}
	if f := strings.Fields(rows[0]); strings.Join(f, " ") != "DOMAIN GRADE SEVERITY CHECK MESSAGE" {
		t.Errorf("unexpected header %q", rows[0])
	}
	if f := strings.Fields(rows[1]); strings.Join(f, " ") != "good.com A - - -" {
		t.Errorf("unexpected row %q", rows[1])
	}
	if f := strings.Fields(rows[2]); len(f) < 5 || f[0] != "weak.com" || f[1] != "B" || f[2] != "warning" || f[3] != "dmarc-policy" {
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
	if code, _, errOut := runCLI(t, "", "-checks", "tls", "good.com"); code != 2 || !strings.Contains(errOut, `unknown check "tls"`) {
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
