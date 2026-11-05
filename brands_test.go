package robertparker_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mikecb/robertparker"
)

var testBrands = []string{"paypal.com", "apple.com", "metamask.io", "bankofamerica.com", "barclays.co.uk", "ups.com", "ledger.com"}

// kindOf returns how name matches, or "" if it doesn't.
func kindOf(t *testing.T, m *robertparker.BrandMatcher, name string) string {
	t.Helper()
	found := m.Match(name)
	if len(found) > 1 {
		t.Errorf("%s matched %d brands: %+v", name, len(found), found)
	}
	if len(found) == 0 {
		return ""
	}
	return found[0].Fuzzer
}

func TestBrandMatchKinds(t *testing.T) {
	m := robertparker.NewBrandMatcher(testBrands, nil)
	for _, tt := range []struct{ name, kind string }{
		{"paypal.xyz", robertparker.MatchOtherSuffix},
		{"paypal.co.uk", robertparker.MatchOtherSuffix},
		{"www.login.paypal.xyz", robertparker.MatchOtherSuffix},
		{"barclays.com", robertparker.MatchOtherSuffix},

		{"paypal.com.example.net", robertparker.MatchBrandDomain},
		{"www.paypal.com.example.net", robertparker.MatchBrandDomain},
		{"barclays.co.uk.example.net", robertparker.MatchBrandDomain},

		{"paypa1.com", robertparker.MatchHomoglyph},
		{"g.paypai.com", robertparker.MatchHomoglyph},
		{"xn--pypal-4ve.com", robertparker.MatchHomoglyph}, // A Cyrillic а.
		{"pаypal.com", robertparker.MatchHomoglyph},        // The same, not yet in punycode.
		{"pàypal.com", robertparker.MatchHomoglyph},        // Accents don't change how it reads.
		{"pay-pal.com", robertparker.MatchHomoglyph},
		{"bank0famer1ca.com", robertparker.MatchHomoglyph},
		{"metarnask.org", robertparker.MatchHomoglyph}, // "rn" for "m".

		{"metanask.cyou", robertparker.MatchTypo},
		{"papal.com", robertparker.MatchTypo},
		{"payapl.com", robertparker.MatchTypo}, // Swapped letters are two edits, but one slip.
		{"paypall.net", robertparker.MatchTypo},
		{"bankofamericaa.com", robertparker.MatchTypo},
		{"banckofamerrica.com", robertparker.MatchTypo}, // Two edits, on a long name.
		{"secure-paypall-login.com", robertparker.MatchTypo},
		{"ldger-live.pages.dev", robertparker.MatchTypo},

		{"paypal-merchant.ru", robertparker.MatchWord},
		{"login-apple.com", robertparker.MatchWord},
		{"apple-id.example.pages.dev", robertparker.MatchSubdomain},
		{"ups-tracking.com", robertparker.MatchWord},
		{"paypa1-login.net", robertparker.MatchWord},
		{"paypal-login.vercel.app", robertparker.MatchWord}, // Anyone can pick a name on a private suffix.
		{"*.paypal-login.com", robertparker.MatchWord},

		{"paypalsecure.com", robertparker.MatchEmbedded},
		{"mypaypal.com", robertparker.MatchEmbedded},
		{"pay-palsecure.com", robertparker.MatchEmbedded},

		{"paypal.example.net", robertparker.MatchSubdomain},
		{"login.apple.example.net", robertparker.MatchSubdomain},
		{"apple-login.example.net", robertparker.MatchSubdomain},
		{"xn--pypal-4ve.example.net", robertparker.MatchSubdomain},
	} {
		if got := kindOf(t, m, tt.name); got != tt.kind {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.kind)
		}
	}
}

func TestBrandMatchLeavesOtherNamesAlone(t *testing.T) {
	m := robertparker.NewBrandMatcher(testBrands, nil)
	for _, name := range []string{
		"paypal.com", "www.paypal.com", "login.paypal.com", "*.paypal.com", "PayPal.com.", // The brand's own.
		"example.com", "com", "co.uk", "", "*.", "not a domain",
		"pineapple.com", "appletree.net", // A short brand inside a word.
		"groups.com", "startups.example.net",
		"finance-ample.net", // A short brand gets no typos inside a longer name.
		"medger.com",        // A different first letter is nearly always another word.
	} {
		if got := m.Match(name); len(got) != 0 {
			t.Errorf("%q matched: %+v", name, got)
		}
	}
}

func TestBrandMatchShortBrandHasNoTypos(t *testing.T) {
	m := robertparker.NewBrandMatcher([]string{"ups.com"}, nil)
	for _, name := range []string{"ups-store.com", "ups.net"} {
		if len(m.Match(name)) != 1 {
			t.Errorf("%s should match", name)
		}
	}
	for _, name := range []string{"upp.com", "up.com", "upsy.com"} {
		if got := m.Match(name); len(got) != 0 {
			t.Errorf("%s matched: %+v", name, got)
		}
	}
}

func TestBrandMatchEveryBrand(t *testing.T) {
	m := robertparker.NewBrandMatcher([]string{"paypal.com", "apple.com"}, nil)
	got := m.Match("paypal-apple.com")
	if len(got) != 2 || got[0].Brand != "paypal.com" || got[1].Brand != "apple.com" {
		t.Errorf("got %+v", got)
	}
}

func TestBrandMatchNames(t *testing.T) {
	m := robertparker.NewBrandMatcher([]string{"paypal.com"}, nil)
	got := m.Match("  *.XN--PYPAL-4VE.com. ")
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	if got[0].ASCII != "xn--pypal-4ve.com" || got[0].Domain != "pаypal.com" || got[0].Brand != "paypal.com" {
		t.Errorf("got %+v", got[0])
	}
}

func TestBrandMatchWithRepeatedBrandLetters(t *testing.T) {
	// "cornell" reads as "comell", so names have to be compared with how the brand reads as well.
	m := robertparker.NewBrandMatcher([]string{"cornell.edu"}, nil)
	for name, kind := range map[string]string{
		"cornell-login.com": robertparker.MatchWord,
		"comell.edu.ph":     robertparker.MatchHomoglyph,
	} {
		if got := kindOf(t, m, name); got != kind {
			t.Errorf("%s: got %q, want %q", name, got, kind)
		}
	}
}

func TestBrandMatchOwned(t *testing.T) {
	m := robertparker.NewBrandMatcher([]string{"amazon.com"}, []string{"amazonaws.com", "amazon.dev", "com"})
	for _, name := range []string{"s3.amazonaws.com", "x.y.amazon.dev"} {
		if got := m.Match(name); len(got) != 0 {
			t.Errorf("%s matched: %+v", name, got)
		}
	}
	if len(m.Match("amazon-login.com")) != 1 {
		t.Error("the other names should still match")
	}
}

func TestBrandMatcherSkipsBrandsWithoutARegistrablePart(t *testing.T) {
	m := robertparker.NewBrandMatcher([]string{"com", "co.uk", ""}, nil)
	if got := m.Match("com.example.net"); len(got) != 0 {
		t.Errorf("got %+v", got)
	}
}

// names is a NameSource for tests.
func names(list ...string) robertparker.NameSource {
	return func(_ context.Context, emit func(robertparker.Sighting)) error {
		for _, name := range list {
			emit(robertparker.Sighting{Name: name, Seen: time.Unix(1000, 0), Source: "test"})
		}
		return nil
	}
}

func collectMatches(t *testing.T, results <-chan robertparker.BrandResult) ([]robertparker.BrandMatch, []error) {
	t.Helper()
	var matches []robertparker.BrandMatch
	var errs []error
	for r := range results {
		if r.Err != nil {
			errs = append(errs, r.Err)
		}
		if r.Match.ASCII != "" {
			matches = append(matches, r.Match)
		}
	}
	return matches, errs
}

func TestFindReportsEachDomainOnce(t *testing.T) {
	m := robertparker.NewBrandMatcher([]string{"paypal.com", "apple.com"}, nil)
	matches, errs := collectMatches(t, m.Find(context.Background(), names(
		"example.net", "paypal-login.com", "www.paypal-login.com", "mail.paypal-login.com", "*.paypal-login.com",
		"a-paypal.pages.dev", "b-paypal.pages.dev", // Separate owners, on a private suffix.
		"paypal-apple.net", // Two brands.
	), nil, 1))
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	var got []string
	for _, match := range matches {
		got = append(got, match.Brand+" "+match.ASCII)
	}
	slices.Sort(got)
	want := []string{"apple.com paypal-apple.net", "paypal.com a-paypal.pages.dev", "paypal.com b-paypal.pages.dev", "paypal.com paypal-apple.net", "paypal.com paypal-login.com"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q", got)
	}
	if matches[0].Source != "test" || !matches[0].Seen.Equal(time.Unix(1000, 0)) {
		t.Errorf("sighting wasn't kept: %+v", matches[0])
	}
}

func TestFindRanksOnWorkers(t *testing.T) {
	m := robertparker.NewBrandMatcher([]string{"paypal.com"}, nil)
	var running, most atomic.Int32
	rank := func(_ context.Context, match *robertparker.BrandMatch) error {
		now := running.Add(1)
		defer running.Add(-1)
		for old := most.Load(); now > old && !most.CompareAndSwap(old, now); old = most.Load() {
		}
		time.Sleep(10 * time.Millisecond)
		match.Suspicion = robertparker.SuspicionHigh
		return nil
	}
	matches, errs := collectMatches(t, m.Find(context.Background(), names("paypal-a.com", "paypal-b.com", "paypal-c.com", "paypal-d.com", "paypal-e.com", "paypal-f.com"), rank, 3))
	if len(errs) != 0 || len(matches) != 6 {
		t.Fatalf("got %d matches, errors %v", len(matches), errs)
	}
	for _, match := range matches {
		if match.Suspicion != robertparker.SuspicionHigh {
			t.Errorf("%s wasn't ranked", match.ASCII)
		}
	}
	if most.Load() != 3 {
		t.Errorf("ran %d at once", most.Load())
	}
}

func TestFindReportsErrors(t *testing.T) {
	m := robertparker.NewBrandMatcher([]string{"paypal.com"}, nil)
	failed := errors.New("no lookups today")
	rank := func(context.Context, *robertparker.BrandMatch) error { return failed }
	matches, errs := collectMatches(t, m.Find(context.Background(), names("paypal-a.com"), rank, 1))
	if len(matches) != 1 || len(errs) != 1 {
		t.Errorf("a failed rank should keep the match: got %+v, %v", matches, errs)
	}

	broken := func(context.Context, func(robertparker.Sighting)) error { return failed }
	if _, errs := collectMatches(t, m.Find(context.Background(), broken, nil, 1)); len(errs) != 1 || !errors.Is(errs[0], failed) {
		t.Errorf("source error: got %v", errs)
	}
}

func TestFindStops(t *testing.T) {
	m := robertparker.NewBrandMatcher([]string{"paypal.com"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	endless := func(ctx context.Context, emit func(robertparker.Sighting)) error {
		for i := 0; ctx.Err() == nil; i++ {
			emit(robertparker.Sighting{Name: "paypal-" + strings.Repeat("a", i%50+1) + ".com"})
		}
		return ctx.Err()
	}
	results := m.Find(ctx, endless, nil, 2)
	<-results
	cancel()
	done := make(chan bool)
	go func() {
		for r := range results {
			if r.Err != nil {
				t.Errorf("stopping isn't an error: %v", r.Err)
			}
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Find didn't stop")
	}
}

func TestNamesFrom(t *testing.T) {
	var got []string
	input := strings.NewReader("# comment\n\n  a.example \nb.example\n")
	err := robertparker.NamesFrom(input)(context.Background(), func(s robertparker.Sighting) { got = append(got, s.Name) })
	if err != nil || !slices.Equal(got, []string{"a.example", "b.example"}) {
		t.Errorf("got %q, %v", got, err)
	}
}

func TestBrandRanker(t *testing.T) {
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	brand := &robertparker.Registration{Registrar: "Brand Registrar", RegistrarID: "1", Registered: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)}
	fresh := &robertparker.Registration{Registrar: "Other", RegistrarID: "2", Registered: now.Add(-48 * time.Hour)}
	old := &robertparker.Registration{Registrar: "Brand Registrar", RegistrarID: "1", Registered: time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)}
	source := rankerRegistrations{"paypal.com": brand, "paypal-login.com": fresh, "example.com": old, "paypal.net": brand}
	dns := &fakeLookalikes{
		hosts: map[string][]string{"paypal-login.com": {"192.0.2.1"}, "example.com": {"192.0.2.2"}, "paypal.net": {"192.0.2.3"}},
		ns:    map[string][]string{"paypal.com": {"ns1.paypal.com."}, "paypal.net": {"ns1.paypal.com."}, "paypal-login.com": {"ns.evil.example."}},
		mx:    map[string][]string{"paypal-login.com": {"mail.evil.example."}},
	}
	ranker := robertparker.NewBrandRanker(dns, source, nil, func() time.Time { return now })
	rank := func(name string) robertparker.BrandMatch {
		t.Helper()
		m := robertparker.NewBrandMatcher([]string{"paypal.com"}, nil).Match(name)
		if len(m) != 1 {
			t.Fatalf("%s didn't match", name)
		}
		if err := ranker.Rank(context.Background(), &m[0]); err != nil {
			t.Fatal(err)
		}
		return m[0]
	}

	if got := rank("www.paypal-login.com"); got.Suspicion != robertparker.SuspicionHigh || got.Registrar != "Other" || len(got.MailServers) != 1 || got.ASCII != "www.paypal-login.com" {
		t.Errorf("a new domain: got %+v", got)
	}
	if got := rank("paypal.example.com"); got.Suspicion != robertparker.SuspicionLow {
		t.Errorf("an old domain with a matching subdomain should be judged by that domain: got %+v", got)
	}
	if got := rank("paypal.net"); got.Suspicion != robertparker.SuspicionLow || !got.SharedNameServers {
		t.Errorf("the brand's own name servers: got %+v", got)
	}
	if got := rank("paypal-login.pages.dev"); got.Suspicion != robertparker.SuspicionUnknown {
		t.Errorf("a private suffix: got %+v", got)
	}
}

func TestBrandRankerFailures(t *testing.T) {
	source := rankerRegistrations{"paypal.com": {Registrar: "Brand"}}
	m := robertparker.NewBrandMatcher([]string{"paypal.com"}, nil).Match("paypal-login.com")[0]
	dns := &fakeLookalikes{failing: map[string]bool{"paypal-login.com": true}}
	ranker := robertparker.NewBrandRanker(dns, source, nil, nil)
	if err := ranker.Rank(context.Background(), &m); err == nil || m.Suspicion != robertparker.SuspicionUnknown {
		t.Errorf("a failed lookup: got %v, %+v", err, m)
	}
}

func TestBrandRankerNameOnlyInAWildcard(t *testing.T) {
	// Nobody has to register a name for it to have a certificate, if its suffix answers for every name.
	dns := &fakeLookalikes{
		hosts:     map[string][]string{"paypal-login.ph": {"192.0.2.9"}},
		wildcards: map[string][]string{"ph": {"192.0.2.9"}},
	}
	source := rankerRegistrations{"paypal.com": {Registrar: "Brand"}}
	m := robertparker.NewBrandMatcher([]string{"paypal.com"}, nil).Match("paypal-login.ph")[0]
	if err := robertparker.NewBrandRanker(dns, source, nil, nil).Rank(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	if m.Suspicion != robertparker.SuspicionLow || len(m.Reasons) != 1 || !strings.Contains(m.Reasons[0], "wildcard") {
		t.Errorf("got %+v", m)
	}
}

// rankerRegistrations answers from a map, and fails for anything else that's asked about.
type rankerRegistrations map[string]*robertparker.Registration

func (r rankerRegistrations) Lookup(_ context.Context, domain string) (*robertparker.Registration, error) {
	if registration, ok := r[domain]; ok {
		return registration, nil
	}
	return nil, errors.New("not expected: " + domain)
}
