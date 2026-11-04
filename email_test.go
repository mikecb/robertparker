package robertparker_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mikecb/robertparker"
)

// fakeDNS is a Resolver backed by a map. A missing name is not found, like a real NXDOMAIN.
type fakeDNS struct {
	records map[string][]string
	failing map[string]bool //Names whose lookups fail.

	mu      sync.Mutex
	queries []string
}

func (f *fakeDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	f.mu.Lock()
	f.queries = append(f.queries, name)
	f.mu.Unlock()
	if f.failing[name] {
		return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	if r, ok := f.records[name]; ok {
		return r, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// goodDMARC is a record that adds no findings.
const goodDMARC = "v=DMARC1; p=reject; rua=mailto:reports@example.com"

// check runs the email checks on domain, and returns "severity check" for each finding, sorted.
func check(t *testing.T, dns *fakeDNS, domain string) []string {
	t.Helper()
	d := robertparker.NewDomain(domain)
	if err := robertparker.EmailAnalyzer(dns, nil)(context.Background(), d); err != nil {
		t.Fatalf("%s: %v", domain, err)
	}
	return summarize(d)
}

func summarize(d *robertparker.Domain) []string {
	got := []string{}
	for _, f := range d.Findings {
		got = append(got, string(f.Severity)+" "+f.Check)
	}
	sort.Strings(got)
	return got
}

func TestSPF(t *testing.T) {
	tests := []struct {
		name    string
		records []string
		extra   map[string][]string
		want    []string
	}{
		{"strict", []string{"v=spf1 ip4:192.0.2.1 -all"}, nil, []string{}},
		{"soft fail", []string{"v=spf1 mx ~all"}, nil, []string{}},
		{"case insensitive", []string{"V=SPF1 MX -ALL"}, nil, []string{}},
		{"ignores other TXT", []string{"google-site-verification=abc", "v=spf1 -all", "v=spf10 x"}, nil, []string{}},
		{"cidr and ipv6", []string{"v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a/24 mx:example.org -all"}, nil, []string{}},
		{"unknown modifier", []string{"v=spf1 foo=bar -all"}, nil, []string{}},
		{"none", nil, nil, []string{"failure spf-record"}},
		{"not spf", []string{"hello"}, nil, []string{"failure spf-record"}},
		{"two records", []string{"v=spf1 -all", "v=spf1 ~all"}, nil, []string{"failure spf-record"}},
		{"plus all", []string{"v=spf1 +all"}, nil, []string{"failure spf-all"}},
		{"bare all", []string{"v=spf1 all"}, nil, []string{"failure spf-all"}},
		{"neutral all", []string{"v=spf1 ?all"}, nil, []string{"warning spf-all"}},
		{"no all", []string{"v=spf1 mx"}, nil, []string{"warning spf-all"}},
		{"ptr", []string{"v=spf1 ptr -all"}, nil, []string{"warning spf-ptr"}},
		{"bad mechanism", []string{"v=spf1 nonsense -all"}, nil, []string{"failure spf-syntax"}},
		{"bad ip4", []string{"v=spf1 ip4:not.an.ip -all"}, nil, []string{"failure spf-syntax"}},
		{"ip6 as ip4", []string{"v=spf1 ip4:2001:db8::1 -all"}, nil, []string{"failure spf-syntax"}},
		{"include without domain", []string{"v=spf1 include: -all"}, nil, []string{"failure spf-syntax"}},
		{"all with value", []string{"v=spf1 all:x"}, nil, []string{"failure spf-syntax", "warning spf-all"}},
		{"include", []string{"v=spf1 include:mail.example.org -all"}, map[string][]string{"mail.example.org": {"v=spf1 +all"}}, []string{}},
		{"missing include", []string{"v=spf1 include:gone.example.org -all"}, nil, []string{"failure spf-include"}},
		{"redirect", []string{"v=spf1 redirect=mail.example.org"}, map[string][]string{"mail.example.org": {"v=spf1 -all"}}, []string{}},
		{"redirect to plus all", []string{"v=spf1 redirect=mail.example.org"}, map[string][]string{"mail.example.org": {"v=spf1 +all"}}, []string{"failure spf-all"}},
		{"redirect ignored after all", []string{"v=spf1 -all redirect=gone.example.org"}, nil, []string{}},
		{"loop", []string{"v=spf1 include:example.com -all"}, nil, []string{}},
		{"macro include", []string{"v=spf1 include:%{d}.example.org -all"}, nil, []string{}},
		{"ten lookups", []string{"v=spf1 " + strings.Repeat("a ", 10) + "-all"}, nil, []string{}},
		{"eleven lookups", []string{"v=spf1 " + strings.Repeat("a ", 11) + "-all"}, nil, []string{"failure spf-lookups"}},
		{
			"lookups in includes count",
			[]string{"v=spf1 include:mail.example.org " + strings.Repeat("mx ", 5) + "-all"},
			map[string][]string{"mail.example.org": {"v=spf1 " + strings.Repeat("a ", 6) + "-all"}},
			[]string{"failure spf-lookups"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns := &fakeDNS{records: map[string][]string{"example.com": tt.records, "_dmarc.example.com": {goodDMARC}}}
			for name, records := range tt.extra {
				dns.records[name] = records
			}
			if tt.records == nil {
				delete(dns.records, "example.com")
			}
			if got := check(t, dns, "example.com"); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDMARC(t *testing.T) {
	tests := []struct {
		name  string
		txt   []string
		extra map[string][]string
		want  []string
	}{
		{"reject", []string{"v=DMARC1; p=reject; rua=mailto:r@example.com"}, nil, []string{}},
		{"quarantine", []string{"v=DMARC1;p=quarantine;rua=mailto:r@example.com"}, nil, []string{}},
		{"spaces and trailing semicolon", []string{"v=DMARC1 ; p = reject ; rua = mailto:r@example.com ;"}, nil, []string{}},
		{"unknown tag ignored", []string{"v=DMARC1; p=reject; rua=mailto:r@example.com; zz=1"}, nil, []string{}},
		{"none", nil, nil, []string{"failure dmarc-record"}},
		{"version not first", []string{"p=reject; v=DMARC1"}, nil, []string{"failure dmarc-record"}},
		{"wrong version case", []string{"v=dmarc1; p=reject"}, nil, []string{"failure dmarc-record"}},
		{"two records", []string{goodDMARC, goodDMARC}, nil, []string{"failure dmarc-record"}},
		{"one valid of two", []string{goodDMARC, "v=spf1 -all"}, nil, []string{}},
		{"monitoring only", []string{"v=DMARC1; p=none; rua=mailto:r@example.com"}, nil, []string{"warning dmarc-policy"}},
		{"no policy with rua", []string{"v=DMARC1; rua=mailto:r@example.com"}, nil, []string{"warning dmarc-policy"}},
		{"no policy without rua", []string{"v=DMARC1"}, nil, []string{"failure dmarc-policy", "warning dmarc-reporting"}},
		{"bad policy with rua", []string{"v=DMARC1; p=block; rua=mailto:r@example.com"}, nil, []string{"warning dmarc-policy"}},
		{"bad policy without rua", []string{"v=DMARC1; p=block"}, nil, []string{"failure dmarc-policy", "warning dmarc-reporting"}},
		{"bad sp", []string{"v=DMARC1; p=reject; sp=block"}, nil, []string{"failure dmarc-policy", "warning dmarc-reporting"}},
		{"valid sp without p", []string{"v=DMARC1; sp=reject; rua=mailto:r@example.com"}, nil, []string{"warning dmarc-policy"}},
		{"weak sp", []string{"v=DMARC1; p=reject; sp=none; rua=mailto:r@example.com"}, nil, []string{"warning dmarc-subdomain-policy"}},
		{"strong sp", []string{"v=DMARC1; p=quarantine; sp=reject; rua=mailto:r@example.com"}, nil, []string{}},
		{"weak np", []string{"v=DMARC1; p=reject; np=quarantine; rua=mailto:r@example.com"}, nil, []string{"warning dmarc-subdomain-policy"}},
		{"np compared with sp", []string{"v=DMARC1; p=reject; sp=quarantine; np=quarantine; rua=mailto:r@example.com"}, nil, []string{"warning dmarc-subdomain-policy"}},
		{"test mode", []string{"v=DMARC1; p=reject; t=y; rua=mailto:r@example.com"}, nil, []string{"warning dmarc-testing"}},
		{"not test mode", []string{"v=DMARC1; p=reject; t=n; rua=mailto:r@example.com"}, nil, []string{}},
		{"removed tags", []string{"v=DMARC1; p=reject; pct=50; ri=3600; rf=afrf; rua=mailto:r@example.com"}, nil, []string{"info dmarc-removed-tag", "info dmarc-removed-tag", "info dmarc-removed-tag"}},
		{"no rua", []string{"v=DMARC1; p=reject"}, nil, []string{"warning dmarc-reporting"}},
		{"bad rua", []string{"v=DMARC1; p=reject; rua=reports"}, nil, []string{"warning dmarc-reporting"}},
		{"report size limit", []string{"v=DMARC1; p=reject; rua=mailto:r@example.com!10m"}, nil, []string{}},
		{"subdomain reports", []string{"v=DMARC1; p=reject; rua=mailto:r@reports.example.com"}, nil, []string{}},
		{"unauthorized reports", []string{"v=DMARC1; p=reject; rua=mailto:r@other.example.org"}, nil, []string{"warning dmarc-report-authorization"}},
		{
			"authorized reports",
			[]string{"v=DMARC1; p=reject; rua=mailto:r@other.example.org"},
			map[string][]string{"example.com._report._dmarc.other.example.org": {"v=DMARC1;"}},
			[]string{},
		},
		{
			"authorization needs a DMARC record",
			[]string{"v=DMARC1; p=reject; rua=mailto:r@other.example.org"},
			map[string][]string{"example.com._report._dmarc.other.example.org": {"hello"}},
			[]string{"warning dmarc-report-authorization"},
		},
		{"inherited", nil, map[string][]string{"_dmarc.com": {"v=DMARC1; p=reject; psd=y; rua=mailto:r@com.example"}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns := &fakeDNS{records: map[string][]string{"example.com": {"v=spf1 -all"}, "_dmarc.example.com": tt.txt}}
			for name, records := range tt.extra {
				dns.records[name] = records
			}
			if tt.txt == nil {
				delete(dns.records, "_dmarc.example.com")
			}
			got := check(t, dns, "example.com")
			if tt.want == nil {
				return // Covered by TestDMARCTreeWalk.
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDMARCTreeWalk(t *testing.T) {
	spf := map[string][]string{"foo.appspot.com": {"v=spf1 -all"}}
	rec := "v=DMARC1; p=reject; rua=mailto:r@appspot.com" // Reports stay within the organization that published it.
	own := "v=DMARC1; p=reject; rua=mailto:r@foo.appspot.com"
	tests := []struct {
		name    string
		records map[string][]string
		queries []string
		want    []string
	}{
		{
			"own record stops at once",
			map[string][]string{"_dmarc.foo.appspot.com": {own}},
			[]string{"_dmarc.foo.appspot.com"},
			[]string{},
		},
		{
			"walks to the top",
			nil,
			[]string{"_dmarc.foo.appspot.com", "_dmarc.appspot.com", "_dmarc.com"},
			[]string{"failure dmarc-record"},
		},
		{
			"inherits from a parent",
			map[string][]string{"_dmarc.appspot.com": {rec}},
			[]string{"_dmarc.foo.appspot.com", "_dmarc.appspot.com", "_dmarc.com"},
			[]string{"info dmarc-record"},
		},
		{
			"psd stops the walk",
			map[string][]string{"_dmarc.appspot.com": {rec + "; psd=y"}, "_dmarc.com": {"v=DMARC1; p=none"}},
			[]string{"_dmarc.foo.appspot.com", "_dmarc.appspot.com"},
			[]string{"info dmarc-record"},
		},
		{
			"psd=u doesn't stop the walk, and the shortest wins",
			map[string][]string{"_dmarc.appspot.com": {rec + "; psd=u"}, "_dmarc.com": {"v=DMARC1; p=none; rua=mailto:r@com.example"}},
			[]string{"_dmarc.foo.appspot.com", "_dmarc.appspot.com", "_dmarc.com"},
			[]string{"info dmarc-record", "warning dmarc-policy", "warning dmarc-report-authorization"},
		},
		{
			"several records at a parent are discarded",
			map[string][]string{"_dmarc.appspot.com": {rec, rec}},
			[]string{"_dmarc.foo.appspot.com", "_dmarc.appspot.com", "_dmarc.com"},
			[]string{"failure dmarc-record"},
		},
		{
			"inherited sp applies",
			map[string][]string{"_dmarc.appspot.com": {"v=DMARC1; p=reject; sp=none; rua=mailto:r@appspot.com"}},
			[]string{"_dmarc.foo.appspot.com", "_dmarc.appspot.com", "_dmarc.com"},
			[]string{"info dmarc-record", "warning dmarc-policy", "warning dmarc-subdomain-policy"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns := &fakeDNS{records: map[string][]string{}}
			for name, records := range spf {
				dns.records[name] = records
			}
			for name, records := range tt.records {
				dns.records[name] = records
			}
			got := check(t, dns, "foo.appspot.com")
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
			var queries []string
			for _, q := range dns.queries {
				if strings.HasPrefix(q, "_dmarc.") {
					queries = append(queries, q)
				}
			}
			if !reflect.DeepEqual(queries, tt.queries) {
				t.Errorf("queried %v, want %v", queries, tt.queries)
			}
		})
	}
}

func TestDMARCTreeWalkLongNames(t *testing.T) {
	dns := &fakeDNS{records: map[string][]string{}}
	d := &robertparker.Domain{Secondary: "a.b.c.d.e.f.g.h.i.j.mail", Suffix: "example.com"}
	robertparker.EmailAnalyzer(dns, nil)(context.Background(), d)
	var dmarc []string
	for _, q := range dns.queries {
		if strings.HasPrefix(q, "_dmarc.") {
			dmarc = append(dmarc, q)
		}
	}
	if len(dmarc) != 8 || dmarc[1] != "_dmarc.g.h.i.j.mail.example.com" {
		t.Errorf("got %d queries, want 8 that skip to 7 labels: %v", len(dmarc), dmarc)
	}
}

func TestEmailLookupFailureIsNotAMissingRecord(t *testing.T) {
	good := map[string][]string{"example.com": {"v=spf1 -all"}, "_dmarc.example.com": {"v=DMARC1; p=reject; rua=mailto:r@other.example.org"}}
	for _, failing := range []string{"example.com", "_dmarc.example.com", "example.com._report._dmarc.other.example.org"} {
		t.Run(failing, func(t *testing.T) {
			dns := &fakeDNS{records: good, failing: map[string]bool{failing: true}}
			d := robertparker.NewDomain("example.com")
			err := robertparker.EmailAnalyzer(dns, nil)(context.Background(), d)
			if err == nil {
				t.Error("want an error from the failed lookup")
			}
			unknown := 0
			for _, f := range d.Findings {
				if f.Severity == robertparker.SeverityFailure {
					t.Errorf("a failed lookup was reported as %+v", f)
				}
				if f.Severity == robertparker.SeverityUnknown {
					unknown++
				}
			}
			if unknown != 1 {
				t.Errorf("got %d unknown findings, want 1: %+v", unknown, d.Findings)
			}
			if g := robertparker.Grade(d); g != "" {
				t.Errorf("got grade %q for an incomplete check, want none", g)
			}
		})
	}
}

func TestSPFIncludeLookupFailure(t *testing.T) {
	dns := &fakeDNS{
		records: map[string][]string{"example.com": {"v=spf1 include:mail.example.org -all"}, "_dmarc.example.com": {goodDMARC}},
		failing: map[string]bool{"mail.example.org": true},
	}
	d := robertparker.NewDomain("example.com")
	if err := robertparker.EmailAnalyzer(dns, nil)(context.Background(), d); err == nil {
		t.Error("want an error from the failed lookup")
	}
	if g := robertparker.Grade(d); g != "" {
		t.Errorf("got grade %q, want none: %+v", g, d.Findings)
	}
}

func TestEmailSkipsBareSuffix(t *testing.T) {
	dns := &fakeDNS{}
	if got := check(t, dns, "appspot.com"); len(got) != 0 || len(dns.queries) != 0 {
		t.Errorf("got findings %v and queries %v for a bare suffix", got, dns.queries)
	}
}

func TestEmailChecksRegistrableDomain(t *testing.T) {
	dns := &fakeDNS{records: map[string][]string{"example.com": {"v=spf1 -all"}, "_dmarc.example.com": {goodDMARC}}}
	if got := check(t, dns, "a.b.example.com"); len(got) != 0 {
		t.Errorf("got %v, want the registrable domain's records to apply", got)
	}
}

func TestEmailUsesPunycode(t *testing.T) {
	dns := &fakeDNS{records: map[string][]string{}}
	check(t, dns, "δοκιμή.com")
	if len(dns.queries) == 0 || dns.queries[0] != "xn--jxalpdlp.com" {
		t.Errorf("queried %v, want the punycode name", dns.queries)
	}
}

func TestGrade(t *testing.T) {
	const w, f, i, u = robertparker.SeverityWarning, robertparker.SeverityFailure, robertparker.SeverityInfo, robertparker.SeverityUnknown
	tests := []struct {
		severities []robertparker.Severity
		want       string
	}{
		{nil, "A"},
		{[]robertparker.Severity{i, i}, "A"},
		{[]robertparker.Severity{w}, "B"},
		{[]robertparker.Severity{w, w}, "C"},
		{[]robertparker.Severity{f}, "D"},
		{[]robertparker.Severity{w, w, w}, "F"},
		{[]robertparker.Severity{f, w}, "F"},
		{[]robertparker.Severity{f, f}, "F"},
		{[]robertparker.Severity{f, f, f, f}, "F"},
		{[]robertparker.Severity{w, u}, ""},
	}
	for _, tt := range tests {
		d := robertparker.NewDomain("example.com")
		for _, s := range tt.severities {
			d.Findings = append(d.Findings, robertparker.Finding{Severity: s})
		}
		if got := robertparker.Grade(d); got != tt.want || d.Grade != tt.want {
			t.Errorf("%v: got %q, stored %q, want %q", tt.severities, got, d.Grade, tt.want)
		}
	}
}

func TestGradeBareSuffix(t *testing.T) {
	if g := robertparker.Grade(robertparker.NewDomain("com")); g != "" {
		t.Errorf("got grade %q for a bare suffix, want none", g)
	}
}

func TestEmailThroughProcess(t *testing.T) {
	records := map[string][]string{}
	var in []string
	for i := 0; i < 200; i++ {
		name := fmt.Sprintf("d%d.com", i)
		in = append(in, name)
		if i%2 == 0 {
			records[name] = []string{"v=spf1 -all"}
			records["_dmarc."+name] = []string{"v=DMARC1; p=reject; rua=mailto:r@" + name}
		}
	}
	dns := &fakeDNS{records: records}
	ctx := context.Background()
	opts := robertparker.Options{
		Workers:   16,
		Analyzers: []robertparker.Analyzer{robertparker.EmailAnalyzer(dns, robertparker.NewLimiter(4, 0)), robertparker.GradeAnalyzer},
	}
	for i, r := range collect(robertparker.Process(ctx, feed(ctx, in), opts)) {
		want := "F"
		if i%2 == 0 {
			want = "A"
		}
		if r.Err != nil || r.Domain.Grade != want {
			t.Errorf("%s: got grade %q, err %v, want %q", r.Input, r.Domain.Grade, r.Err, want)
		}
	}
}

// slowDNS never answers until the context is done.
type slowDNS struct{}

func (slowDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestEmailTimeout(t *testing.T) {
	ctx := context.Background()
	opts := robertparker.Options{
		Timeout:   20 * time.Millisecond,
		Analyzers: []robertparker.Analyzer{robertparker.EmailAnalyzer(slowDNS{}, nil), robertparker.GradeAnalyzer},
	}
	results := collect(robertparker.Process(ctx, feed(ctx, []string{"example.com"}), opts))
	if len(results) != 1 || !errors.Is(results[0].Err, context.DeadlineExceeded) || results[0].Domain.Grade != "" {
		t.Errorf("want a deadline error and no grade, got %+v", results)
	}
}
