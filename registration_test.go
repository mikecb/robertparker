package robertparker_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mikecb/robertparker"
)

// rdapRecord builds an RDAP response like the ones Verisign sends.
func rdapRecord(registrar, id, registered string) string {
	return fmt.Sprintf(`{
		"objectClassName": "domain",
		"entities": [
			{"objectClassName": "entity", "roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Not the registrar"]]]},
			{
				"objectClassName": "entity",
				"roles": ["registrar"],
				"publicIds": [{"type": "IANA Registrar ID", "identifier": %q}],
				"vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", %q]]]
			}
		],
		"events": [
			{"eventAction": "registration", "eventDate": %q},
			{"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}
		]
	}`, id, registrar, registered)
}

// rdapServer is a fake registry, with IANA's list of servers at /dns.json.
func rdapServer(t *testing.T, handler http.HandlerFunc) *robertparker.RDAP {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dns.json" {
			fmt.Fprintf(w, `{"services": [[["com", "net"], ["%s/rdap/"]], [["org"], ["%s/org/"]]]}`, server.URL, server.URL)
			return
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	return &robertparker.RDAP{Bootstrap: server.URL + "/dns.json"}
}

func TestRDAPLookup(t *testing.T) {
	var path, accept, agent string
	r := rdapServer(t, func(w http.ResponseWriter, req *http.Request) {
		path, accept, agent = req.URL.Path, req.Header.Get("Accept"), req.UserAgent()
		fmt.Fprint(w, rdapRecord("MarkMonitor Inc.", "292", "2007-10-09T18:20:50Z"))
	})
	got, err := r.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := &robertparker.Registration{Registrar: "MarkMonitor Inc.", RegistrarID: "292", Registered: time.Date(2007, 10, 9, 18, 20, 50, 0, time.UTC)}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if path != "/rdap/domain/example.com" || !strings.Contains(accept, "application/rdap+json") || !strings.HasPrefix(agent, "robertparker ") {
		t.Errorf("requested %s, Accept %q, User-Agent %q", path, accept, agent)
	}
}

func TestRDAPUsesEachTLDsServer(t *testing.T) {
	var path string
	r := rdapServer(t, func(w http.ResponseWriter, req *http.Request) {
		path = req.URL.Path
		fmt.Fprint(w, "{}")
	})
	if _, err := r.Lookup(context.Background(), "example.org"); err != nil {
		t.Fatal(err)
	}
	if path != "/org/domain/example.org" {
		t.Errorf("requested %s", path)
	}
}

func TestRDAPNoData(t *testing.T) {
	requests := 0
	r := rdapServer(t, func(w http.ResponseWriter, req *http.Request) {
		requests++
		http.NotFound(w, req)
	})
	for _, domain := range []string{"unregistered.com", "example.io"} {
		if got, err := r.Lookup(context.Background(), domain); got != nil || err != nil {
			t.Errorf("%s: got %+v, %v, want no data and no error", domain, got, err)
		}
	}
	if requests != 1 {
		t.Errorf("made %d requests, want none for a TLD with no server", requests)
	}
}

func TestRDAPMissingDetails(t *testing.T) {
	r := rdapServer(t, func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, `{"events": [{"eventAction": "registration", "eventDate": "not a date"}], "entities": [{"roles": ["registrar"]}]}`)
	})
	got, err := r.Lookup(context.Background(), "example.com")
	if err != nil || got == nil || got.Registrar != "" || !got.Registered.IsZero() {
		t.Errorf("got %+v, %v, want an empty registration", got, err)
	}
}

func TestRDAPBadResponses(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"server error": func(w http.ResponseWriter, req *http.Request) {
			http.Error(w, "broken", http.StatusInternalServerError)
		},
		"not json": func(w http.ResponseWriter, req *http.Request) { fmt.Fprint(w, "<html>") },
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := rdapServer(t, handler).Lookup(context.Background(), "example.com"); err == nil {
				t.Errorf("got %+v, want an error", got)
			}
		})
	}
}

func TestRDAPRetriesWhenThrottled(t *testing.T) {
	var requests atomic.Int64
	r := rdapServer(t, func(w http.ResponseWriter, req *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, rdapRecord("A", "1", "2020-01-01T00:00:00Z"))
	})
	start := time.Now()
	got, err := r.Lookup(context.Background(), "example.com")
	if err != nil || got == nil || got.Registrar != "A" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if time.Since(start) < 900*time.Millisecond {
		t.Errorf("took %v, want it to wait as Retry-After said", time.Since(start))
	}
}

func TestRDAPGivesUpWhenThrottled(t *testing.T) {
	var requests atomic.Int64
	r := rdapServer(t, func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	if _, err := r.Lookup(context.Background(), "example.com"); err == nil || requests.Load() != 3 {
		t.Errorf("got %v after %d requests, want an error after 3", err, requests.Load())
	}
}

func TestRDAPCancelledWhileThrottled(t *testing.T) {
	r := rdapServer(t, func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Retry-After", "20")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := r.Lookup(ctx, "example.com"); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Errorf("got %v after %v", err, time.Since(start))
	}
}

func TestRDAPBootstrapFailureIsRetried(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dns.json" {
			if fail.Load() {
				http.Error(w, "broken", http.StatusBadGateway)
				return
			}
			fmt.Fprintf(w, `{"services": [[["com"], ["%s/"]]]}`, server.URL)
			return
		}
		fmt.Fprint(w, rdapRecord("A", "1", "2020-01-01T00:00:00Z"))
	}))
	defer server.Close()
	r := &robertparker.RDAP{Bootstrap: server.URL + "/dns.json"}
	if _, err := r.Lookup(context.Background(), "example.com"); err == nil {
		t.Fatal("want an error from a failed bootstrap")
	}
	fail.Store(false)
	if got, err := r.Lookup(context.Background(), "example.com"); err != nil || got == nil {
		t.Errorf("got %+v, %v, want a later lookup to work", got, err)
	}
}

func TestRDAPLimitsEachServer(t *testing.T) {
	var running, peak atomic.Int64
	r := rdapServer(t, func(w http.ResponseWriter, req *http.Request) {
		n := running.Add(1)
		defer running.Add(-1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		time.Sleep(20 * time.Millisecond)
		fmt.Fprint(w, "{}")
	})
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 11; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Lookup(context.Background(), fmt.Sprintf("d%d.com", i))
		}()
	}
	wg.Wait()
	if peak.Load() > 4 {
		t.Errorf("peak of %d requests at once, want at most 4", peak.Load())
	}
	if time.Since(start) < 900*time.Millisecond {
		t.Errorf("11 requests took %v, want the rate limit of 10 a second", time.Since(start))
	}
}

// fakeSource is a RegistrationSource backed by a map.
type fakeSource struct {
	registrations map[string]*robertparker.Registration
	failing       map[string]bool

	mu      sync.Mutex
	queries []string
}

func (f *fakeSource) Lookup(_ context.Context, domain string) (*robertparker.Registration, error) {
	f.mu.Lock()
	f.queries = append(f.queries, domain)
	f.mu.Unlock()
	if f.failing[domain] {
		return nil, errors.New("rdap broke")
	}
	return f.registrations[domain], nil
}

var regNow = time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)

func fixedNow() time.Time { return regNow }

func old(registrar, id string) *robertparker.Registration {
	return &robertparker.Registration{Registrar: registrar, RegistrarID: id, Registered: regNow.AddDate(-10, 0, 0)}
}

func recent(registrar, id string) *robertparker.Registration {
	return &robertparker.Registration{Registrar: registrar, RegistrarID: id, Registered: regNow.AddDate(0, -2, 0)}
}

func TestSuspicion(t *testing.T) {
	canonical := old("Brand Registrar", "1")
	tests := []struct {
		name         string
		lookalike    robertparker.Lookalike
		registration *robertparker.Registration
		canonical    *robertparker.Registration
		want         robertparker.Suspicion
		reasons      []string
	}{
		{"only a different registrar", robertparker.Lookalike{}, old("Other", "2"), canonical, robertparker.SuspicionLow, []string{"has a different registrar from the original"}},
		{
			"recent, different registrar",
			robertparker.Lookalike{}, recent("Other", "2"), canonical, robertparker.SuspicionHigh,
			[]string{"has a different registrar from the original", "was registered in the last year"},
		},
		{
			"parked with mail",
			robertparker.Lookalike{MailServers: []string{"mx.example"}}, old("Other", "2"), canonical, robertparker.SuspicionMedium,
			[]string{"has a different registrar from the original", "can receive mail"},
		},
		{
			"everything",
			robertparker.Lookalike{MailServers: []string{"mx.example"}}, recent("Other", "2"), canonical, robertparker.SuspicionHigh,
			[]string{"has a different registrar from the original", "was registered in the last year", "can receive mail"},
		},
		{
			"the same registrar doesn't clear it",
			robertparker.Lookalike{MailServers: []string{"mx.example"}}, recent("Brand Registrar", "1"), canonical, robertparker.SuspicionHigh,
			[]string{"was registered in the last year", "can receive mail"},
		},
		{"recent, same registrar", robertparker.Lookalike{}, recent("Brand Registrar", "1"), canonical, robertparker.SuspicionMedium, []string{"was registered in the last year"}},
		{"same ID, renamed", robertparker.Lookalike{}, old("Brand Registrar, LLC", "1"), canonical, robertparker.SuspicionLow, nil},
		{"same name, no IDs", robertparker.Lookalike{}, old("brand registrar", ""), old("Brand Registrar", ""), robertparker.SuspicionLow, nil},
		{"shared name servers", robertparker.Lookalike{SharedNameServers: true}, recent("Other", "2"), canonical, robertparker.SuspicionLow, []string{"shares name servers with the original"}},
		{"shared name servers, no data", robertparker.Lookalike{SharedNameServers: true}, nil, canonical, robertparker.SuspicionLow, []string{"shares name servers with the original"}},
		{"no lookalike data", robertparker.Lookalike{MailServers: []string{"mx.example"}}, nil, canonical, robertparker.SuspicionUnknown, nil},
		{"no canonical data", robertparker.Lookalike{}, recent("Other", "2"), nil, robertparker.SuspicionUnknown, nil},
		{"no registrar in the data", robertparker.Lookalike{}, &robertparker.Registration{Registered: regNow}, canonical, robertparker.SuspicionUnknown, nil},
		{"no date", robertparker.Lookalike{}, &robertparker.Registration{Registrar: "Other", RegistrarID: "2"}, canonical, robertparker.SuspicionLow, []string{"has a different registrar from the original"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := robertparker.NewDomain("example.com")
			l := tt.lookalike
			l.ASCII = "exmaple.com"
			d.Lookalikes = []robertparker.Lookalike{l}
			f := &fakeSource{registrations: map[string]*robertparker.Registration{"example.com": tt.canonical, "exmaple.com": tt.registration}}
			if err := robertparker.RegistrationAnalyzer(f, fixedNow)(context.Background(), d); err != nil {
				t.Fatal(err)
			}
			got := d.Lookalikes[0]
			if got.Suspicion != tt.want || !reflect.DeepEqual(got.Reasons, tt.reasons) {
				t.Errorf("got %s %q, want %s %q", got.Suspicion, got.Reasons, tt.want, tt.reasons)
			}
			if tt.registration != nil && (got.Registrar != tt.registration.Registrar || !got.Registered.Equal(tt.registration.Registered)) {
				t.Errorf("registration wasn't copied: %+v", got)
			}
		})
	}
}

func TestRecentBoundary(t *testing.T) {
	for days, want := range map[int]robertparker.Suspicion{364: robertparker.SuspicionHigh, 366: robertparker.SuspicionLow} {
		d := robertparker.NewDomain("example.com")
		d.Lookalikes = []robertparker.Lookalike{{ASCII: "exmaple.com"}}
		f := &fakeSource{registrations: map[string]*robertparker.Registration{
			"example.com": old("A", "1"),
			"exmaple.com": {Registrar: "B", RegistrarID: "2", Registered: regNow.AddDate(0, 0, -days)},
		}}
		robertparker.RegistrationAnalyzer(f, fixedNow)(context.Background(), d)
		if got := d.Lookalikes[0].Suspicion; got != want {
			t.Errorf("%d days: got %s, want %s", days, got, want)
		}
	}
}

func TestLookalikesSortedBySuspicion(t *testing.T) {
	d := robertparker.NewDomain("example.com")
	mail := []string{"mx.example"}
	d.Lookalikes = []robertparker.Lookalike{{ASCII: "low.com"}, {ASCII: "unknown.com"}, {ASCII: "medium.com", MailServers: mail}, {ASCII: "medium2.com", MailServers: mail}, {ASCII: "high.com"}}
	f := &fakeSource{registrations: map[string]*robertparker.Registration{
		"example.com": old("A", "1"),
		"low.com":     old("A", "1"),
		"medium.com":  old("B", "2"),
		"medium2.com": old("B", "2"),
		"high.com":    recent("B", "2"),
	}}
	if err := robertparker.RegistrationAnalyzer(f, fixedNow)(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	want := []string{"high.com", "medium.com", "medium2.com", "unknown.com", "low.com"}
	if got := asciiNames(d); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestRegistrationUsesTheRegisteredDomain(t *testing.T) {
	d := robertparker.NewDomain("example.com")
	d.Lookalikes = []robertparker.Lookalike{{ASCII: "exam.ple.com"}, {ASCII: "exmaple.co.uk"}}
	f := &fakeSource{}
	robertparker.RegistrationAnalyzer(f, fixedNow)(context.Background(), d)
	got := map[string]bool{}
	for _, q := range f.queries {
		got[q] = true
	}
	if !got["ple.com"] || !got["exmaple.co.uk"] || got["exam.ple.com"] {
		t.Errorf("queried %v", f.queries)
	}
}

func TestRegistrationSkipsPrivateSuffixes(t *testing.T) {
	d := robertparker.NewDomain("foo.appspot.com")
	d.Lookalikes = []robertparker.Lookalike{{ASCII: "fo.appspot.com"}}
	f := &fakeSource{}
	if err := robertparker.RegistrationAnalyzer(f, fixedNow)(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if len(f.queries) != 0 || d.Lookalikes[0].Suspicion != robertparker.SuspicionUnknown {
		t.Errorf("queried %v, got %+v", f.queries, d.Lookalikes)
	}
}

func TestRegistrationNoLookalikes(t *testing.T) {
	f := &fakeSource{}
	if err := robertparker.RegistrationAnalyzer(f, fixedNow)(context.Background(), robertparker.NewDomain("example.com")); err != nil || len(f.queries) != 0 {
		t.Errorf("got %v, queried %v", err, f.queries)
	}
}

func TestRegistrationLookupFailure(t *testing.T) {
	d := robertparker.NewDomain("example.com")
	d.Lookalikes = []robertparker.Lookalike{{ASCII: "exmaple.com"}, {ASCII: "exampel.com"}}
	f := &fakeSource{
		registrations: map[string]*robertparker.Registration{"example.com": old("A", "1"), "exampel.com": old("B", "2")},
		failing:       map[string]bool{"exmaple.com": true},
	}
	err := robertparker.RegistrationAnalyzer(f, fixedNow)(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "1 of 2") || d.RegistrationFailures != 1 {
		t.Fatalf("got %v, %d failures", err, d.RegistrationFailures)
	}
	want := []robertparker.Suspicion{robertparker.SuspicionUnknown, robertparker.SuspicionLow}
	got := []robertparker.Suspicion{d.Lookalikes[0].Suspicion, d.Lookalikes[1].Suspicion}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want a failed lookup to be unknown, not suspicious", got)
	}
}

func TestRegistrationCanonicalFailure(t *testing.T) {
	d := robertparker.NewDomain("example.com")
	d.Lookalikes = []robertparker.Lookalike{{ASCII: "exmaple.com"}, {ASCII: "exampel.com"}}
	f := &fakeSource{failing: map[string]bool{"example.com": true}}
	err := robertparker.RegistrationAnalyzer(f, fixedNow)(context.Background(), d)
	if err == nil || d.RegistrationFailures != 2 || d.Lookalikes[0].Suspicion != robertparker.SuspicionUnknown || len(f.queries) != 1 {
		t.Errorf("got %v, %d failures, %+v, %d queries", err, d.RegistrationFailures, d.Lookalikes, len(f.queries))
	}
}

func TestLookalikeDatesInJSON(t *testing.T) {
	out, err := json.Marshal(robertparker.Lookalike{ASCII: "a.com"})
	if err != nil || strings.Contains(string(out), "Registered") {
		t.Errorf("a zero date should be left out: %s, %v", out, err)
	}
}

func TestRegistrationThroughProcess(t *testing.T) {
	dns := &fakeLookalikes{hosts: map[string][]string{"exmaple.com": {"192.0.2.1"}, "gogle.com": {"192.0.2.2"}}}
	source := &fakeSource{registrations: map[string]*robertparker.Registration{
		"example.com": old("A", "1"), "google.com": old("A", "1"),
		"exmaple.com": old("A", "1"), "gogle.com": recent("B", "2"),
	}}
	ctx := context.Background()
	opts := robertparker.Options{Workers: 4, Analyzers: []robertparker.Analyzer{
		robertparker.LookalikeAnalyzer(dns, nil),
		robertparker.RegistrationAnalyzer(source, fixedNow),
	}}
	results := collect(robertparker.Process(ctx, feed(ctx, []string{"example.com", "google.com"}), opts))
	if len(results) != 2 || results[0].Err != nil || results[1].Err != nil {
		t.Fatalf("%+v", results)
	}
	if got := results[0].Domain.Lookalikes[0].Suspicion; got != robertparker.SuspicionLow {
		t.Errorf("example.com: %s", got)
	}
	if got := results[1].Domain.Lookalikes[0].Suspicion; got != robertparker.SuspicionHigh {
		t.Errorf("google.com: %s", got)
	}
}
