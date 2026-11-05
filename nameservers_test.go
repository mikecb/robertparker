package robertparker_test

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mikecb/robertparker"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	ns1v4    = "198.51.100.1"
	ns1v6    = "2001::1"
	ns2v4    = "203.0.113.1"
	parentv4 = "192.0.2.53"
	parentv6 = "2001:db8::53"
)

// internet is the servers that can be reached directly, by address. Anything else doesn't answer.
type internet map[string]*dnsServer

// zoneServer is a name server for the example.com of healthyZone.
func zoneServer() *dnsServer {
	zone := healthyZone()
	return &dnsServer{answers: map[string][]dnsmessage.ResourceBody{zoneSOA: zone[zoneSOA], zoneNS: zone[zoneNS]}}
}

// comServer is a server for the zone above, that refers queries for example.com to hosts.
func comServer(hosts ...string) *dnsServer {
	return &dnsServer{notAuthoritative: true, authorities: map[string][]dnsmessage.ResourceBody{zoneNS: nsAt(hosts...)}}
}

// healthyInternet is what healthyZone needs in order to have nothing wrong.
func healthyInternet() internet {
	referral := comServer("ns1.example.net.", "ns2.example.org.")
	return internet{ns1v4: zoneServer(), ns1v6: zoneServer(), ns2v4: zoneServer(), parentv4: referral, parentv6: referral}
}

// route starts the servers, and returns the function that sends queries to them. It records where they were meant to go.
func (n internet) route(t *testing.T) (func(string) string, func() []string) {
	t.Helper()
	nowhere, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := nowhere.LocalAddr().String()
	nowhere.Close()

	var started []*dnsServer
	for _, s := range n {
		if !slices.Contains(started, s) {
			startDNS(t, s)
			started = append(started, s)
		}
	}
	var mu sync.Mutex
	var attempted []string
	rewrite := func(address string) string {
		mu.Lock()
		defer mu.Unlock()
		attempted = append(attempted, address)
		host, _, _ := net.SplitHostPort(address)
		if s, ok := n[host]; ok {
			return s.addr
		}
		return closed
	}
	return rewrite, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(attempted)
	}
}

// checkZone checks example.com, with zone at the resolver, and the name servers on n.
func checkZone(t *testing.T, zone map[string][]dnsmessage.ResourceBody, n internet) (*robertparker.Domain, error) {
	t.Helper()
	rewrite, _ := n.route(t)
	address := startDNS(t, &dnsServer{answers: zone})
	d := robertparker.NewDomain("example.com")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := robertparker.DNSAnalyzerRouted(address, nil, rewrite)(ctx, d)
	robertparker.Grade(d)
	return d, err
}

// messages returns the messages of one check.
func messages(d *robertparker.Domain, check string) string {
	var found []string
	for _, f := range d.Findings {
		if f.Check == check {
			found = append(found, f.Message)
		}
	}
	return strings.Join(found, "\n")
}

func TestNameServersHealthy(t *testing.T) {
	n := healthyInternet()
	d, err := checkZone(t, healthyZone(), n)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range d.Findings {
		if f.Severity != robertparker.SeverityInfo || f.Check == "dns-ns-untested" {
			t.Errorf("found %+v", f)
		}
	}
	for address, s := range n {
		if len(s.asked()) == 0 {
			t.Errorf("didn't ask %s", address)
		}
		s.mu.Lock()
		if s.recursive {
			t.Errorf("asked %s to recurse", address)
		}
		s.mu.Unlock()
	}
}

func TestNameServerProblems(t *testing.T) {
	const (
		warning = robertparker.SeverityWarning
		failure = robertparker.SeverityFailure
	)
	tests := []struct {
		name     string
		change   func(n internet)
		check    string
		severity robertparker.Severity
		message  string
	}{
		{"refuses the zone", func(n internet) {
			n[ns2v4] = &dnsServer{rcode: dnsmessage.RCodeRefused}
		}, "dns-ns-lame", failure, "ns2.example.org answers Refused"},
		{"isn't an authority", func(n internet) {
			s := zoneServer()
			s.notAuthoritative = true
			n[ns2v4] = s
		}, "dns-ns-lame", failure, "ns2.example.org doesn't answer for the zone"},
		{"has no SOA", func(n internet) {
			n[ns2v4] = &dnsServer{}
		}, "dns-ns-lame", failure, "ns2.example.org doesn't answer for the zone"},
		{"doesn't reply", func(n internet) {
			delete(n, ns2v4)
		}, "dns-ns-respond", warning, "ns2.example.org didn't reply"},
		{"parent lists one the zone doesn't", func(n internet) {
			referral := comServer("ns1.example.net.", "ns2.example.org.", "ns3.example.net.")
			n[parentv4], n[parentv6] = referral, referral
		}, "dns-ns-parent", warning, "The parent zone lists name servers the zone doesn't: ns3.example.net."},
		{"zone lists one the parent doesn't", func(n internet) {
			referral := comServer("ns1.example.net.")
			n[parentv4], n[parentv6] = referral, referral
		}, "dns-ns-parent", warning, "The zone lists name servers the parent doesn't: ns2.example.org."},
		{"no TCP", func(n internet) {
			n[ns2v4].noTCP = true
		}, "dns-ns-tcp", warning, "ns2.example.org doesn't answer over TCP"},
		{"no answer over IPv6", func(n internet) {
			delete(n, ns1v6)
		}, "dns-ns-ipv6-answer", warning, "ns1.example.net has an IPv6 address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := healthyInternet()
			tt.change(n)
			d, err := checkZone(t, healthyZone(), n)
			if err != nil {
				t.Fatal(err)
			}
			if got := severities(d)[tt.check]; got != tt.severity {
				t.Errorf("%s was %q, want %q, in %+v", tt.check, got, tt.severity, d.Findings)
			}
			if got := messages(d, tt.check); !strings.Contains(got, tt.message) {
				t.Errorf("got %q, want %q", got, tt.message)
			}
		})
	}
}

// If the servers can't be asked, it's the network running this, because the domain did resolve.
func TestNameServersOutOfReach(t *testing.T) {
	blocked := func(n internet) {
		delete(n, ns1v4)
		delete(n, ns2v4)
	}
	redirected := func(n internet) {
		for _, address := range []string{ns1v4, ns2v4} {
			n[address].notAuthoritative = true
		}
	}
	for name, change := range map[string]func(internet){"blocked": blocked, "redirected": redirected} {
		t.Run(name, func(t *testing.T) {
			n := healthyInternet()
			change(n)
			d, err := checkZone(t, healthyZone(), n)
			if err == nil {
				t.Error("no error")
			}
			if got := severities(d)["dns-ns-lame"]; got != robertparker.SeverityUnknown {
				t.Errorf("got %q, in %+v", got, d.Findings)
			}
			if got := d.Grades[robertparker.AreaDNS]; got != "" {
				t.Errorf("got grade %q", got)
			}
			if _, found := severities(d)["dns-ns-respond"]; found {
				t.Errorf("blamed the servers: %+v", d.Findings)
			}
		})
	}
}

// A server that didn't get to reply because time ran out says nothing about the server.
func TestNameServersOutOfTime(t *testing.T) {
	n := healthyInternet()
	n[ns2v4].silent = 1000
	rewrite, _ := n.route(t)
	address := startDNS(t, &dnsServer{answers: healthyZone()})
	d := robertparker.NewDomain("example.com")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := robertparker.DNSAnalyzerRouted(address, nil, rewrite)(ctx, d); err == nil {
		t.Error("no error")
	}
	if _, found := severities(d)["dns-ns-respond"]; found {
		t.Errorf("blamed the server: %+v", d.Findings)
	}
	if robertparker.Grade(d) != "" {
		t.Errorf("got grade %q", d.Grade)
	}
}

func TestNameServersUntestedFromHere(t *testing.T) {
	t.Run("TCP", func(t *testing.T) {
		n := healthyInternet()
		n[parentv4].noTCP, n[ns1v4].noTCP, n[ns2v4].noTCP = true, true, true
		d, err := checkZone(t, healthyZone(), n)
		if err != nil {
			t.Fatal(err)
		}
		if _, found := severities(d)["dns-ns-tcp"]; found {
			t.Errorf("blamed the servers: %+v", d.Findings)
		}
		if got := messages(d, "dns-ns-untested"); !strings.Contains(got, "TCP") {
			t.Errorf("got %q", got)
		}
	})
	t.Run("IPv6", func(t *testing.T) {
		n := healthyInternet()
		delete(n, parentv6)
		delete(n, ns1v6)
		d, err := checkZone(t, healthyZone(), n)
		if err != nil {
			t.Fatal(err)
		}
		if _, found := severities(d)["dns-ns-ipv6-answer"]; found {
			t.Errorf("blamed the server: %+v", d.Findings)
		}
		if got := messages(d, "dns-ns-untested"); !strings.Contains(got, "IPv6") {
			t.Errorf("got %q", got)
		}
	})
	t.Run("a server with only IPv6", func(t *testing.T) {
		zone := healthyZone()
		delete(zone, "ns1.example.net. TypeA")
		n := healthyInternet()
		delete(n, parentv6)
		delete(n, ns1v4)
		delete(n, ns1v6)
		d, err := checkZone(t, zone, n)
		if err != nil {
			t.Fatal(err)
		}
		if _, found := severities(d)["dns-ns-respond"]; found {
			t.Errorf("blamed the server: %+v", d.Findings)
		}
	})
}

func TestNameServerSerials(t *testing.T) {
	withSerial := func(serial uint32) *dnsServer {
		s := zoneServer()
		s.answers[zoneSOA] = []dnsmessage.ResourceBody{&dnsmessage.SOAResource{
			NS: name("ns1.example.net."), MBox: name("admin.example.net."),
			Serial: serial, Refresh: 7200, Retry: 900, Expire: 1209600, MinTTL: 3600,
		}}
		return s
	}
	t.Run("one provider", func(t *testing.T) {
		zone := healthyZone()
		zone[zoneNS] = nsAt("ns1.example.net.", "ns2.example.net.")
		zone["ns2.example.net. TypeA"] = ipv4(203, 0, 113, 1)
		referral := comServer("ns1.example.net.", "ns2.example.net.")
		n := internet{ns1v4: withSerial(2), ns1v6: withSerial(2), ns2v4: withSerial(1), parentv4: referral, parentv6: referral}
		for _, address := range []string{ns1v4, ns1v6, ns2v4} {
			n[address].answers[zoneNS] = zone[zoneNS]
		}
		d, err := checkZone(t, zone, n)
		if err != nil {
			t.Fatal(err)
		}
		if got := severities(d)["dns-ns-serial"]; got != robertparker.SeverityWarning {
			t.Errorf("got %q, in %+v", got, d.Findings)
		}
	})
	// Two providers number a zone separately, and having two is a strong setup.
	t.Run("two providers", func(t *testing.T) {
		n := healthyInternet()
		n[ns1v4], n[ns1v6], n[ns2v4] = withSerial(1656468023), withSerial(1656468023), withSerial(1)
		d, err := checkZone(t, healthyZone(), n)
		if err != nil {
			t.Fatal(err)
		}
		if got := severities(d)["dns-ns-serial"]; got != robertparker.SeverityInfo {
			t.Errorf("got %q, in %+v", got, d.Findings)
		}
	})
}

func TestNameServersOfTwoProvidersListOnlyTheirOwn(t *testing.T) {
	n := healthyInternet()
	for address, host := range map[string]string{ns1v4: "ns1.example.net.", ns1v6: "ns1.example.net.", ns2v4: "ns2.example.org."} {
		n[address].answers[zoneNS] = nsAt(host)
	}
	d, err := checkZone(t, healthyZone(), n)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := severities(d)["dns-ns-parent"]; found {
		t.Errorf("got %+v", d.Findings)
	}
}

func TestParentThatAlsoRunsTheZone(t *testing.T) {
	n := healthyInternet()
	both := zoneServer()
	n[parentv4], n[parentv6] = both, both
	d, err := checkZone(t, healthyZone(), n)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := severities(d)["dns-ns-parent"]; found {
		t.Errorf("got %+v", d.Findings)
	}
}

func TestNameServersAtInternalAddressesAreNotAsked(t *testing.T) {
	var mapped [16]byte
	mapped[10], mapped[11], mapped[12], mapped[15] = 0xff, 0xff, 10, 1
	var loopback [16]byte
	loopback[15] = 1
	tests := []struct {
		name string
		ipv4 []dnsmessage.ResourceBody
		ipv6 []dnsmessage.ResourceBody
	}{
		{"private", ipv4(10, 0, 0, 1), nil},
		{"loopback", ipv4(127, 0, 0, 1), nil},
		{"link-local", ipv4(169, 254, 169, 254), nil},
		{"shared", ipv4(100, 64, 0, 1), nil},
		{"IPv6 loopback", nil, []dnsmessage.ResourceBody{&dnsmessage.AAAAResource{AAAA: loopback}}},
		{"private as IPv6", nil, []dnsmessage.ResourceBody{&dnsmessage.AAAAResource{AAAA: mapped}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone := healthyZone()
			zone["ns1.example.net. TypeA"], zone["ns1.example.net. TypeAAAA"] = tt.ipv4, tt.ipv6
			n := healthyInternet()
			rewrite, attempted := n.route(t)
			d := robertparker.NewDomain("example.com")
			address := startDNS(t, &dnsServer{answers: zone})
			if err := robertparker.DNSAnalyzerRouted(address, nil, rewrite)(context.Background(), d); err != nil {
				t.Fatal(err)
			}
			if got := messages(d, "dns-ns-resolve"); !strings.Contains(got, "can't be reached from the internet") {
				t.Errorf("got %q, in %+v", got, d.Findings)
			}
			for _, a := range attempted() {
				if a != net.JoinHostPort(ns2v4, "53") && !strings.HasPrefix(a, parentv4) && !strings.Contains(a, parentv6) {
					t.Errorf("sent a query to %s", a)
				}
			}
		})
	}
}

func TestParentIsLookedUpOnce(t *testing.T) {
	n := healthyInternet()
	rewrite, _ := n.route(t)
	resolver := &dnsServer{answers: healthyZone()}
	analyzer := robertparker.DNSAnalyzerRouted(startDNS(t, resolver), nil, rewrite)
	for range 3 {
		if err := analyzer(context.Background(), robertparker.NewDomain("example.com")); err != nil {
			t.Fatal(err)
		}
	}
	lookups := 0
	for _, q := range resolver.asked() {
		if q == "com. TypeNS" {
			lookups++
		}
	}
	if lookups != 1 {
		t.Errorf("looked it up %d times", lookups)
	}
}

func TestParentFailureIsNotKept(t *testing.T) {
	n := healthyInternet()
	rewrite, _ := n.route(t)
	zone := healthyZone()
	parent := zone["com. TypeNS"]
	delete(zone, "com. TypeNS")
	for _, key := range []string{zoneAAAA, zoneDS, zoneDNSKEY, "ns2.example.org. TypeAAAA", "mail.example.com. TypeA"} {
		zone[key] = nil
	}
	resolver := &dnsServer{answers: zone, rcode: dnsmessage.RCodeServerFailure}
	analyzer := robertparker.DNSAnalyzerRouted(startDNS(t, resolver), nil, rewrite)

	d := robertparker.NewDomain("example.com")
	if err := analyzer(context.Background(), d); err == nil {
		t.Error("no error")
	}
	if got := severities(d)["dns-ns-parent"]; got != robertparker.SeverityUnknown {
		t.Errorf("got %q, in %+v", got, d.Findings)
	}

	resolver.mu.Lock()
	zone["com. TypeNS"] = parent
	resolver.mu.Unlock()
	d = robertparker.NewDomain("example.com")
	if err := analyzer(context.Background(), d); err != nil {
		t.Errorf("after the failure: %v", err)
	}
}

// Not every level of a public suffix is a zone of its own, like ac.uk here.
func TestParentIsTheNearestZoneAbove(t *testing.T) {
	zone := map[string][]dnsmessage.ResourceBody{
		"example.ac.uk. TypeNS":  nsAt("ns1.example.net."),
		"example.ac.uk. TypeSOA": soaWith(7200, 900, 1209600, 3600),
		"example.ac.uk. 257":     {caa(0, "issue", "letsencrypt.org")},
		"ns1.example.net. TypeA": ipv4(198, 51, 100, 1),
		"uk. TypeNS":             nsAt("a.nic.example."),
		"a.nic.example. TypeA":   ipv4(192, 0, 2, 53),
	}
	server := &dnsServer{answers: map[string][]dnsmessage.ResourceBody{
		"example.ac.uk. TypeNS":  zone["example.ac.uk. TypeNS"],
		"example.ac.uk. TypeSOA": zone["example.ac.uk. TypeSOA"],
	}}
	parent := &dnsServer{notAuthoritative: true, authorities: map[string][]dnsmessage.ResourceBody{
		"example.ac.uk. TypeNS": nsAt("ns1.example.net."),
	}}
	n := internet{ns1v4: server, parentv4: parent}
	rewrite, _ := n.route(t)
	address := startDNS(t, &dnsServer{answers: zone})
	d := robertparker.NewDomain("example.ac.uk")
	if err := robertparker.DNSAnalyzerRouted(address, nil, rewrite)(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(parent.asked(), "example.ac.uk. TypeNS") {
		t.Errorf("didn't ask the parent, got %+v", d.Findings)
	}
}

// With checking disabled, a resolver can pass on an empty answer from one server, which is no reason to say that the
// domain is offline.
func TestDNSSECKeysAreConfirmedWithTheNameServers(t *testing.T) {
	key := newTestKey(t, 13, entryFlags)
	zone := healthyZone()
	zone[zoneDS] = []dnsmessage.ResourceBody{dsFor(key.data, 13, false)}

	t.Run("a server has them", func(t *testing.T) {
		n := healthyInternet()
		n[ns2v4].answers[zoneDNSKEY] = []dnsmessage.ResourceBody{key.record()}
		d, err := checkZone(t, zone, n)
		if err != nil {
			t.Fatal(err)
		}
		if got := severities(d)["dnssec-chain"]; got == robertparker.SeverityFailure {
			t.Errorf("got %+v", d.Findings)
		}
	})
	t.Run("no server has them", func(t *testing.T) {
		d, err := checkZone(t, zone, healthyInternet())
		if err != nil {
			t.Fatal(err)
		}
		if got := severities(d)["dnssec-chain"]; got != robertparker.SeverityFailure {
			t.Errorf("got %q, in %+v", got, d.Findings)
		}
	})
}
