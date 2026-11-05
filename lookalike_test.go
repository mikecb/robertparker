package robertparker_test

import (
	"context"
	"errors"
	"net"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mikecb/robertparker"
)

// fakeLookalikes is a LookalikeResolver backed by maps. A missing name is not found.
type fakeLookalikes struct {
	hosts       map[string][]string
	ns          map[string][]string
	mx          map[string][]string
	failing     map[string]bool     //Names whose lookups time out.
	servfail    map[string]bool     //Names that get a server failure.
	servfailAll bool                //Every name gets a server failure, as if the resolver were broken.
	wildcards   map[string][]string //Suffixes that answer for every name, and what with.
	delay       time.Duration

	mu      sync.Mutex
	queries []string
	running atomic.Int64
	peak    atomic.Int64
}

func (f *fakeLookalikes) answer(ctx context.Context, name string) error {
	f.mu.Lock()
	f.queries = append(f.queries, name)
	f.mu.Unlock()
	n := f.running.Add(1)
	defer f.running.Add(-1)
	for p := f.peak.Load(); n > p && !f.peak.CompareAndSwap(p, n); p = f.peak.Load() {
	}
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if f.servfail[name] || f.servfailAll {
		return &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	if f.failing[name] {
		return &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true}
	}
	return ctx.Err()
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeLookalikes) LookupHost(ctx context.Context, name string) ([]string, error) {
	if err := f.answer(ctx, name); err != nil {
		return nil, err
	}
	if h, ok := f.hosts[name]; ok {
		return slices.Clone(h), nil
	}
	for suffix, addresses := range f.wildcards {
		if strings.HasSuffix(name, "."+suffix) {
			return slices.Clone(addresses), nil
		}
	}
	return nil, notFound(name)
}

func (f *fakeLookalikes) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	if err := f.answer(ctx, name); err != nil {
		return nil, err
	}
	var records []*net.NS
	for _, host := range f.ns[name] {
		records = append(records, &net.NS{Host: host})
	}
	if records == nil {
		return nil, notFound(name)
	}
	return records, nil
}

func (f *fakeLookalikes) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if err := f.answer(ctx, name); err != nil {
		return nil, err
	}
	var records []*net.MX
	for _, host := range f.mx[name] {
		records = append(records, &net.MX{Host: host})
	}
	if records == nil {
		return nil, notFound(name)
	}
	return records, nil
}

func lookup(t *testing.T, f *fakeLookalikes, domain string) *robertparker.Domain {
	t.Helper()
	d := robertparker.NewDomain(domain)
	if err := robertparker.LookalikeAnalyzer(f, nil)(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	return d
}

func asciiNames(d *robertparker.Domain) []string {
	names := []string{}
	for _, l := range d.Lookalikes {
		names = append(names, l.ASCII)
	}
	return names
}

func TestLookalikesFound(t *testing.T) {
	f := &fakeLookalikes{
		hosts: map[string][]string{"exmaple.com": {"192.0.2.2", "192.0.2.1"}, "example.net": {"192.0.2.9"}},
		ns:    map[string][]string{"exmaple.com": {"ns2.parked.example.", "NS1.Parked.Example."}, "exampel.com": {"ns1.other.example."}},
		mx:    map[string][]string{"exmaple.com": {"mail.exmaple.com."}},
	}
	d := lookup(t, f, "www.example.com")
	want := []robertparker.Lookalike{
		{Fuzzer: "transposition", Domain: "exmaple.com", ASCII: "exmaple.com", Addresses: []string{"192.0.2.1", "192.0.2.2"}, NameServers: []string{"ns1.parked.example", "ns2.parked.example"}, MailServers: []string{"mail.exmaple.com"}},
		{Fuzzer: "transposition", Domain: "exampel.com", ASCII: "exampel.com", NameServers: []string{"ns1.other.example"}},
		{Fuzzer: "tld-swap", Domain: "example.net", ASCII: "example.net", Addresses: []string{"192.0.2.9"}},
	}
	if !reflect.DeepEqual(d.Lookalikes, want) {
		t.Errorf("got %+v, want %+v", d.Lookalikes, want)
	}
	if d.Permutations != nil || d.LookupFailures != 0 {
		t.Errorf("Permutations %d, LookupFailures %d", len(d.Permutations), d.LookupFailures)
	}
}

func TestLookalikesNoneFound(t *testing.T) {
	if d := lookup(t, &fakeLookalikes{}, "example.com"); len(d.Lookalikes) != 0 {
		t.Errorf("got %+v", d.Lookalikes)
	}
}

func TestLookalikesKeepPermutations(t *testing.T) {
	f := &fakeLookalikes{}
	d := robertparker.NewDomain("example.com")
	want := robertparker.Permute(d)
	if err := robertparker.LookalikeAnalyzer(f, nil)(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d.Permutations, want) {
		t.Error("Permutations changed")
	}
}

func TestLookalikesNullMX(t *testing.T) {
	f := &fakeLookalikes{hosts: map[string][]string{"exmaple.com": {"192.0.2.1"}}, mx: map[string][]string{"exmaple.com": {"."}}}
	d := lookup(t, f, "example.com")
	if len(d.Lookalikes) != 1 || len(d.Lookalikes[0].MailServers) != 0 {
		t.Errorf("a null MX means it takes no mail, got %+v", d.Lookalikes)
	}
}

func TestLookalikesSharedNameServers(t *testing.T) {
	f := &fakeLookalikes{ns: map[string][]string{
		"example.com": {"alice.ns.host.example.", "bob.ns.host.example."},
		"exmaple.com": {"bob.ns.host.example."},                             // A subset of the original's.
		"exampel.com": {"carol.ns.host.example.", "dave.ns.host.example."},  // Same provider, but a different account.
		"exapmle.com": {"alice.ns.host.example.", "carol.ns.host.example."}, // One in common can be chance.
		"exampl.com":  {"ns1.someone-else.example."},
	}}
	d := lookup(t, f, "example.com")
	shared := map[string]bool{}
	for _, l := range d.Lookalikes {
		shared[l.ASCII] = l.SharedNameServers
	}
	want := map[string]bool{"exmaple.com": true, "exampel.com": false, "exapmle.com": false, "exampl.com": false}
	if !reflect.DeepEqual(shared, want) {
		t.Errorf("got %v, want %v", shared, want)
	}
}

func TestLookalikesWildcardSuffix(t *testing.T) {
	f := &fakeLookalikes{
		wildcards: map[string][]string{"com": {"203.0.113.1"}, "net": {"203.0.113.2"}},
		hosts:     map[string][]string{"exmaple.com": {"203.0.113.1", "192.0.2.5"}},
		ns:        map[string][]string{"exampel.com": {"ns1.other.example."}},
	}
	d := lookup(t, f, "example.com")
	want := []string{"exmaple.com", "exampel.com"}
	if got := asciiNames(d); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want only names with more than the wildcard's answer: %v", got, want)
	}
	if !reflect.DeepEqual(d.Lookalikes[0].Addresses, []string{"192.0.2.5"}) {
		t.Errorf("the wildcard's address should be dropped: %+v", d.Lookalikes[0])
	}
}

func TestLookalikesWildcardTestedOncePerSuffix(t *testing.T) {
	f := &fakeLookalikes{hosts: map[string][]string{"exmaple.com": {"192.0.2.1"}, "exampel.com": {"192.0.2.1"}, "exmple.com": {"192.0.2.1"}}}
	analyzer := robertparker.LookalikeAnalyzer(f, nil)
	for _, domain := range []string{"example.com", "example.com"} {
		if err := analyzer(context.Background(), robertparker.NewDomain(domain)); err != nil {
			t.Fatal(err)
		}
	}
	probes := map[string]bool{}
	for _, q := range f.queries {
		if strings.HasPrefix(q, "robertparker-") {
			probes[q] = true
		}
	}
	if len(probes) > 2 { // Concurrent lookups may race to be first, but it must not be once per lookalike.
		t.Errorf("%d wildcard tests for one suffix: %v", len(probes), probes)
	}
}

func TestLookalikesFailedLookups(t *testing.T) {
	f := &fakeLookalikes{
		hosts:   map[string][]string{"exmaple.com": {"192.0.2.1"}},
		failing: map[string]bool{"exampel.com": true, "exapmle.com": true},
	}
	d := robertparker.NewDomain("example.com")
	err := robertparker.LookalikeAnalyzer(f, nil)(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "2 of") || !strings.Contains(err.Error(), "i/o timeout") {
		t.Errorf("got error %v, want a count and the cause", err)
	}
	if d.LookupFailures != 2 {
		t.Errorf("got %d failures, want 2", d.LookupFailures)
	}
	if got := asciiNames(d); !reflect.DeepEqual(got, []string{"exmaple.com"}) {
		t.Errorf("the rest should still be found, got %v", got)
	}
}

func TestLookalikesWildcardFailure(t *testing.T) {
	f := &fakeLookalikes{hosts: map[string][]string{"exmaple.com": {"192.0.2.1"}}}
	f2 := &failingProbe{f}
	d := robertparker.NewDomain("example.com")
	if err := robertparker.LookalikeAnalyzer(f2, nil)(context.Background(), d); err == nil || d.LookupFailures != 1 || len(d.Lookalikes) != 0 {
		t.Errorf("a failed wildcard test must not report the name as found: err %v, %d failures, %+v", err, d.LookupFailures, d.Lookalikes)
	}
}

// failingProbe fails the wildcard test.
type failingProbe struct{ *fakeLookalikes }

func (f *failingProbe) LookupHost(ctx context.Context, name string) ([]string, error) {
	if strings.HasPrefix(name, "robertparker-") {
		return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	return f.fakeLookalikes.LookupHost(ctx, name)
}

func TestLookalikesCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := robertparker.NewDomain("example.com")
	err := robertparker.LookalikeAnalyzer(&fakeLookalikes{}, nil)(ctx, d)
	if !errors.Is(err, context.Canceled) || d.LookupFailures == 0 {
		t.Errorf("got %v, %d failures", err, d.LookupFailures)
	}
}

func TestLookalikesConcurrencyIsBounded(t *testing.T) {
	f := &fakeLookalikes{delay: time.Millisecond}
	lookup(t, f, "example.com")
	if p := f.peak.Load(); p > 16 || p < 8 {
		t.Errorf("peak of %d lookups at once, want up to 16", p)
	}
}

func TestLookalikesWaitingForTheLimiterIsNotATimeout(t *testing.T) {
	f := &fakeLookalikes{}
	d := robertparker.NewDomain("example.com")
	// The queue is what takes the time here. A timeout that counted it would fail these lookups.
	limiter := robertparker.NewLimiter(1, 1500)
	opts := robertparker.LookalikeAnalyzer(f, limiter)
	start := time.Now()
	if err := opts(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 100*time.Millisecond {
		t.Error("the limiter wasn't used")
	}
}

func TestLookalikesSkipBareSuffix(t *testing.T) {
	f := &fakeLookalikes{}
	if d := lookup(t, f, "appspot.com"); len(f.queries) != 0 || d.Lookalikes != nil {
		t.Errorf("queried %v", f.queries)
	}
}

func TestLookalikesOfPrivateSuffix(t *testing.T) {
	f := &fakeLookalikes{hosts: map[string][]string{"fo.appspot.com": {"192.0.2.1"}}}
	d := lookup(t, f, "bar.foo.appspot.com")
	if got := asciiNames(d); !reflect.DeepEqual(got, []string{"fo.appspot.com"}) {
		t.Errorf("got %v", got)
	}
}

func TestLookalikesUsePunycode(t *testing.T) {
	f := &fakeLookalikes{hosts: map[string][]string{"xn--xample-2of.com": {"192.0.2.1"}}}
	d := lookup(t, f, "example.com")
	if len(d.Lookalikes) != 1 || d.Lookalikes[0].Domain != "еxample.com" || d.Lookalikes[0].ASCII != "xn--xample-2of.com" {
		t.Errorf("got %+v", d.Lookalikes)
	}
}

func TestLookalikesThroughProcess(t *testing.T) {
	f := &fakeLookalikes{hosts: map[string][]string{"gogle.com": {"192.0.2.1"}, "exmaple.com": {"192.0.2.2"}}}
	ctx := context.Background()
	opts := robertparker.Options{
		Workers:   4,
		Analyzers: []robertparker.Analyzer{robertparker.LookalikeAnalyzer(f, robertparker.NewLimiter(8, 0))},
	}
	results := collect(robertparker.Process(ctx, feed(ctx, []string{"google.com", "example.com"}), opts))
	if len(results) != 2 || results[0].Err != nil || results[1].Err != nil {
		t.Fatalf("%+v", results)
	}
	if got := asciiNames(results[0].Domain); !reflect.DeepEqual(got, []string{"gogle.com"}) {
		t.Errorf("google.com: %v", got)
	}
	if got := asciiNames(results[1].Domain); !reflect.DeepEqual(got, []string{"exmaple.com"}) {
		t.Errorf("example.com: %v", got)
	}
}

// flakyHost fails each name's first few lookups.
type flakyHost struct {
	*fakeLookalikes
	failures int
	mu       sync.Mutex
	seen     map[string]int
}

func (f *flakyHost) LookupHost(ctx context.Context, name string) ([]string, error) {
	f.mu.Lock()
	f.seen[name]++
	n := f.seen[name]
	f.mu.Unlock()
	if n <= f.failures {
		return nil, &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true}
	}
	return f.fakeLookalikes.LookupHost(ctx, name)
}

func TestLookalikesRetryDroppedQueries(t *testing.T) {
	f := &flakyHost{fakeLookalikes: &fakeLookalikes{hosts: map[string][]string{"exmaple.com": {"192.0.2.1"}}}, failures: 2, seen: map[string]int{}}
	d := robertparker.NewDomain("example.com")
	if err := robertparker.LookalikeAnalyzer(f, nil)(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if got := asciiNames(d); !reflect.DeepEqual(got, []string{"exmaple.com"}) || d.LookupFailures != 0 {
		t.Errorf("got %v, %d failures", got, d.LookupFailures)
	}
}

func TestLookalikesGiveUpAfterRetries(t *testing.T) {
	f := &flakyHost{fakeLookalikes: &fakeLookalikes{}, failures: 3, seen: map[string]int{}}
	d := robertparker.NewDomain("example.com")
	if err := robertparker.LookalikeAnalyzer(f, nil)(context.Background(), d); err == nil || d.LookupFailures == 0 {
		t.Errorf("got err %v, %d failures", err, d.LookupFailures)
	}
	if n := f.seen["exmaple.com"]; n != 3 {
		t.Errorf("tried %d times, want 3", n)
	}
}

func TestLookalikesRetryKeepsNoDuplicates(t *testing.T) {
	f := &flakyNS{fakeLookalikes: &fakeLookalikes{ns: map[string][]string{"exmaple.com": {"ns1.other.example."}}}}
	d := robertparker.NewDomain("example.com")
	if err := robertparker.LookalikeAnalyzer(f, nil)(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if len(d.Lookalikes) != 1 || len(d.Lookalikes[0].NameServers) != 1 {
		t.Errorf("got %+v", d.Lookalikes)
	}
}

// flakyNS returns a partial answer with an error the first time for each name.
type flakyNS struct {
	*fakeLookalikes
	seen sync.Map
}

func (f *flakyNS) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	records, err := f.fakeLookalikes.LookupNS(ctx, name)
	if _, retried := f.seen.LoadOrStore(name, true); !retried && err == nil {
		return records, &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true}
	}
	return records, err
}

func TestLookalikesServerFailureMeansRegistered(t *testing.T) {
	f := &fakeLookalikes{servfail: map[string]bool{"exmaple.com": true}}
	d := lookup(t, f, "example.com")
	want := []robertparker.Lookalike{{Fuzzer: "transposition", Domain: "exmaple.com", ASCII: "exmaple.com", BrokenDNS: true}}
	if !reflect.DeepEqual(d.Lookalikes, want) || d.LookupFailures != 0 {
		t.Errorf("got %+v, %d failures", d.Lookalikes, d.LookupFailures)
	}
}

func TestLookalikesWindowsServerFailure(t *testing.T) {
	f := &windowsServFail{fakeLookalikes: &fakeLookalikes{}}
	d := robertparker.NewDomain("example.com")
	if err := robertparker.LookalikeAnalyzer(f, nil)(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if len(d.Lookalikes) != 1 || !d.Lookalikes[0].BrokenDNS {
		t.Errorf("got %+v", d.Lookalikes)
	}
}

// windowsServFail fails one name the way the Windows resolver does.
type windowsServFail struct{ *fakeLookalikes }

func (f *windowsServFail) LookupHost(ctx context.Context, name string) ([]string, error) {
	if name == "exmaple.com" {
		return nil, &net.DNSError{Err: "dnsquery: DNS server failure.", Name: name}
	}
	return f.fakeLookalikes.LookupHost(ctx, name)
}

func TestLookalikesBrokenResolverIsNotRegistered(t *testing.T) {
	// If the resolver is what's failing, every name fails, and none of them should count as registered.
	f := &fakeLookalikes{servfailAll: true}
	d := robertparker.NewDomain("example.com")
	err := robertparker.LookalikeAnalyzer(f, nil)(context.Background(), d)
	if err == nil || len(d.Lookalikes) != 0 || d.LookupFailures == 0 {
		t.Errorf("got err %v, %d lookalikes, %d failures", err, len(d.Lookalikes), d.LookupFailures)
	}
}

func TestLookalikesPartialAnswer(t *testing.T) {
	f := &partialDNS{fakeLookalikes: &fakeLookalikes{
		hosts: map[string][]string{"exmaple.com": {"192.0.2.1"}},
		ns:    map[string][]string{"exmaple.com": {"ns1.other.example."}},
		mx:    map[string][]string{"exmaple.com": {"mail.exmaple.com."}},
	}}
	d := robertparker.NewDomain("example.com")
	if err := robertparker.LookalikeAnalyzer(f, nil)(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if len(d.Lookalikes) != 1 || len(d.Lookalikes[0].NameServers) != 1 || len(d.Lookalikes[0].MailServers) != 1 {
		t.Errorf("good records should survive a malformed one: %+v", d.Lookalikes)
	}
}

// partialDNS returns good records with an error, as Go does when some in the response are malformed.
type partialDNS struct{ *fakeLookalikes }

func malformed(name string) error {
	return &net.DNSError{Err: "DNS response contained records which contain invalid names", Name: name}
}

func (f *partialDNS) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	records, err := f.fakeLookalikes.LookupNS(ctx, name)
	if err == nil {
		return records, malformed(name)
	}
	return records, err
}

func (f *partialDNS) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	records, err := f.fakeLookalikes.LookupMX(ctx, name)
	if err == nil {
		return records, malformed(name)
	}
	return records, err
}

func TestLookalikesMailServerFailure(t *testing.T) {
	f := &brokenMX{fakeLookalikes: &fakeLookalikes{hosts: map[string][]string{"exmaple.com": {"192.0.2.1"}}}}
	d := robertparker.NewDomain("example.com")
	if err := robertparker.LookalikeAnalyzer(f, nil)(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if len(d.Lookalikes) != 1 || d.Lookalikes[0].BrokenDNS {
		t.Errorf("got %+v", d.Lookalikes)
	}
}

// brokenMX gets a server failure for every MX lookup.
type brokenMX struct{ *fakeLookalikes }

func (f *brokenMX) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
}

func TestLookalikesOnlyMalformedRecords(t *testing.T) {
	f := &malformedHost{fakeLookalikes: &fakeLookalikes{}}
	d := robertparker.NewDomain("example.com")
	if err := robertparker.LookalikeAnalyzer(f, nil)(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if len(d.Lookalikes) != 1 || !d.Lookalikes[0].BrokenDNS {
		t.Errorf("got %+v", d.Lookalikes)
	}
}

// malformedHost answers one name with records too malformed to use.
type malformedHost struct{ *fakeLookalikes }

func (f *malformedHost) LookupHost(ctx context.Context, name string) ([]string, error) {
	if name == "exmaple.com" {
		return nil, malformed(name)
	}
	return f.fakeLookalikes.LookupHost(ctx, name)
}
