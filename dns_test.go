package robertparker_test

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mikecb/robertparker"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	zoneNS     = "example.com. TypeNS"
	zoneSOA    = "example.com. TypeSOA"
	zoneA      = "example.com. TypeA"
	zoneAAAA   = "example.com. TypeAAAA"
	zoneMX     = "example.com. TypeMX"
	zoneCAA    = "example.com. 257"
	zoneDS     = "example.com. 43"
	zoneDNSKEY = "example.com. 48"
)

func nsAt(hosts ...string) []dnsmessage.ResourceBody {
	var bodies []dnsmessage.ResourceBody
	for _, host := range hosts {
		bodies = append(bodies, &dnsmessage.NSResource{NS: name(host)})
	}
	return bodies
}

func soaWith(refresh, retry, expire, negative uint32) []dnsmessage.ResourceBody {
	return []dnsmessage.ResourceBody{&dnsmessage.SOAResource{
		NS: name("ns1.example.net."), MBox: name("admin.example.net."),
		Serial: 1, Refresh: refresh, Retry: retry, Expire: expire, MinTTL: negative,
	}}
}

func caa(flags byte, tag, value string) dnsmessage.ResourceBody {
	data := append([]byte{flags, byte(len(tag))}, tag+value...)
	return &dnsmessage.UnknownResource{Type: 257, Data: data}
}

func ipv4(a, b, c, d byte) []dnsmessage.ResourceBody {
	return []dnsmessage.ResourceBody{&dnsmessage.AResource{A: [4]byte{a, b, c, d}}}
}

// healthyZone is a zone with nothing wrong, in the middle of every suggested range.
func healthyZone() map[string][]dnsmessage.ResourceBody {
	var ipv6 [16]byte
	ipv6[0], ipv6[1], ipv6[15] = 0x20, 0x01, 1
	return map[string][]dnsmessage.ResourceBody{
		zoneNS:                   nsAt("ns1.example.net.", "ns2.example.org."),
		zoneSOA:                  soaWith(7200, 900, 1209600, 3600),
		zoneA:                    ipv4(192, 0, 2, 1),
		zoneMX:                   {&dnsmessage.MXResource{Pref: 10, MX: name("mail.example.com.")}},
		zoneCAA:                  {caa(0, "issue", "letsencrypt.org")},
		"ns1.example.net. TypeA": ipv4(198, 51, 100, 1),
		"ns2.example.org. TypeA": ipv4(203, 0, 113, 1),
		"ns1.example.net. TypeAAAA": {
			&dnsmessage.AAAAResource{AAAA: ipv6},
		},
		"com. TypeNS":             nsAt("a.tld.example."),
		"a.tld.example. TypeA":    ipv4(192, 0, 2, 53),
		"a.tld.example. TypeAAAA": {&dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 0x53}}},
	}
}

// checkDNS runs the checks on example.com, with s as the resolver and every name server, and grades it.
func checkDNS(t *testing.T, s *dnsServer) (*robertparker.Domain, error) {
	t.Helper()
	address := startDNS(t, s)
	d := robertparker.NewDomain("example.com")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := robertparker.DNSAnalyzerRouted(address, nil, func(string) string { return address })(ctx, d)
	robertparker.Grade(d)
	return d, err
}

// severities returns the worst severity found for each check.
func severities(d *robertparker.Domain) map[string]robertparker.Severity {
	rank := map[robertparker.Severity]int{robertparker.SeverityInfo: 1, robertparker.SeverityWarning: 2, robertparker.SeverityFailure: 3, robertparker.SeverityUnknown: 4}
	worst := map[string]robertparker.Severity{}
	for _, f := range d.Findings {
		if rank[f.Severity] > rank[worst[f.Check]] {
			worst[f.Check] = f.Severity
		}
	}
	return worst
}

func TestDNSHealthyZone(t *testing.T) {
	d, err := checkDNS(t, &dnsServer{answers: healthyZone()})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range d.Findings {
		if f.Severity != robertparker.SeverityInfo {
			t.Errorf("found %+v", f)
		}
		if f.Area != robertparker.AreaDNS {
			t.Errorf("area of %+v", f)
		}
	}
	if d.Grades[robertparker.AreaDNS] != "A" {
		t.Errorf("got grades %v", d.Grades)
	}
}

func TestDNSChecks(t *testing.T) {
	const (
		warning = robertparker.SeverityWarning
		failure = robertparker.SeverityFailure
		info    = robertparker.SeverityInfo
	)
	tests := []struct {
		name     string
		change   func(z map[string][]dnsmessage.ResourceBody)
		check    string
		severity robertparker.Severity
		grade    string
	}{
		{"one name server", func(z map[string][]dnsmessage.ResourceBody) {
			z[zoneNS] = nsAt("ns1.example.net.")
		}, "dns-ns-count", warning, "A"},
		{"name servers on one network", func(z map[string][]dnsmessage.ResourceBody) {
			z["ns1.example.net. TypeA"] = ipv4(203, 0, 113, 2)
		}, "dns-ns-network", warning, "A"},
		{"name server that doesn't resolve", func(z map[string][]dnsmessage.ResourceBody) {
			delete(z, "ns2.example.org. TypeA")
		}, "dns-ns-resolve", failure, "D"},
		{"name server that's a CNAME", func(z map[string][]dnsmessage.ResourceBody) {
			z["ns1.example.net. TypeA"] = append([]dnsmessage.ResourceBody{&dnsmessage.CNAMEResource{CNAME: name("other.example.net.")}}, z["ns1.example.net. TypeA"]...)
		}, "dns-ns-cname", warning, "A"},
		{"no IPv6 on the name servers", func(z map[string][]dnsmessage.ResourceBody) {
			delete(z, "ns1.example.net. TypeAAAA")
		}, "dns-ns-ipv6", info, "A"},
		{"no SOA on any server", func(z map[string][]dnsmessage.ResourceBody) {
			delete(z, zoneSOA)
		}, "dns-soa", failure, "F"},
		{"SOA retry longer than refresh", func(z map[string][]dnsmessage.ResourceBody) {
			z[zoneSOA] = soaWith(3600, 7200, 1209600, 3600)
		}, "dns-soa-timers", warning, "A"},
		{"SOA expire too short", func(z map[string][]dnsmessage.ResourceBody) {
			z[zoneSOA] = soaWith(3600, 900, 1800, 3600)
		}, "dns-soa-timers", warning, "A"},
		// The timers of large, well-run zones, which are outside RFC 1912's ranges and shouldn't cost anything.
		{"short timers that agree", func(z map[string][]dnsmessage.ResourceBody) {
			z[zoneSOA] = soaWith(900, 900, 1800, 60)
		}, "dns-soa-timers", info, "A"},
		{"long negative caching", func(z map[string][]dnsmessage.ResourceBody) {
			z[zoneSOA] = soaWith(7200, 900, 1209600, 86400)
		}, "dns-soa-timers", info, "A"},
		{"private address", func(z map[string][]dnsmessage.ResourceBody) {
			z[zoneA] = ipv4(10, 0, 0, 1)
		}, "dns-address", warning, "A"},
		{"loopback address", func(z map[string][]dnsmessage.ResourceBody) {
			z[zoneA] = ipv4(127, 0, 0, 1)
		}, "dns-address", warning, "A"},
		{"mail server that's a CNAME", func(z map[string][]dnsmessage.ResourceBody) {
			z["mail.example.com. TypeA"] = append([]dnsmessage.ResourceBody{&dnsmessage.CNAMEResource{CNAME: name("mail.example.net.")}}, ipv4(192, 0, 2, 25)...)
		}, "dns-mx-cname", warning, "A"},
		{"no CAA", func(z map[string][]dnsmessage.ResourceBody) {
			delete(z, zoneCAA)
		}, "dns-caa", warning, "A"},
		{"CAA with only a report address", func(z map[string][]dnsmessage.ResourceBody) {
			z[zoneCAA] = []dnsmessage.ResourceBody{caa(0, "iodef", "mailto:a@example.com")}
		}, "dns-caa", warning, "A"},
		{"CAA with only wildcards", func(z map[string][]dnsmessage.ResourceBody) {
			z[zoneCAA] = []dnsmessage.ResourceBody{caa(0, "issuewild", ";")}
		}, "dns-caa", warning, "A"},
		{"CAA with a critical property CAs don't know", func(z map[string][]dnsmessage.ResourceBody) {
			z[zoneCAA] = append(z[zoneCAA], caa(128, "madeup", "x"))
		}, "dns-caa-critical", failure, "D"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone := healthyZone()
			tt.change(zone)
			d, err := checkDNS(t, &dnsServer{answers: zone})
			if err != nil {
				t.Fatal(err)
			}
			if got := severities(d)[tt.check]; got != tt.severity {
				t.Errorf("%s was %q, want %q, in %+v", tt.check, got, tt.severity, d.Findings)
			}
			if got := d.Grades[robertparker.AreaDNS]; got != tt.grade {
				t.Errorf("got grade %q, want %q, from %+v", got, tt.grade, d.Findings)
			}
		})
	}
}

// Exchange Online's servers fail CNAME queries, which mustn't stop a domain being graded.
func TestDNSNeverAsksForCNAMEs(t *testing.T) {
	s := &dnsServer{answers: healthyZone()}
	if _, err := checkDNS(t, s); err != nil {
		t.Fatal(err)
	}
	for _, q := range s.asked() {
		if strings.HasSuffix(q, "TypeCNAME") {
			t.Errorf("asked %q", q)
		}
	}
}

func TestDNSNullMX(t *testing.T) {
	zone := healthyZone()
	zone[zoneMX] = []dnsmessage.ResourceBody{&dnsmessage.MXResource{Pref: 0, MX: name(".")}}
	s := &dnsServer{answers: zone}
	d, err := checkDNS(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Grades[robertparker.AreaDNS]; got != "A" {
		t.Errorf("got grade %q from %+v", got, d.Findings)
	}
	for _, q := range s.asked() {
		if strings.HasPrefix(q, ". ") {
			t.Errorf("looked up the root: %q", q)
		}
	}
}

func TestDNSIPv6OnlyNameServersResolve(t *testing.T) {
	zone := healthyZone()
	zone[zoneNS] = nsAt("ns1.example.net.")
	delete(zone, "ns1.example.net. TypeA")
	d, err := checkDNS(t, &dnsServer{answers: zone})
	if err != nil {
		t.Fatal(err)
	}
	if _, found := severities(d)["dns-ns-resolve"]; found {
		t.Errorf("got %+v", d.Findings)
	}
}

// signedKey is a DNSKEY record, and the same record as the DS digests cover it.
func signedKey(algorithm byte) (*dnsmessage.UnknownResource, []byte) {
	data := append([]byte{0x01, 0x01, 3, algorithm}, "made-up public key"...)
	return &dnsmessage.UnknownResource{Type: 48, Data: data}, data
}

// dsFor returns a DS record for key, using SHA-256 or, if weak, SHA-1.
func dsFor(key []byte, algorithm byte, weak bool) *dnsmessage.UnknownResource {
	message := append([]byte("\x07example\x03com\x00"), key...)
	data := []byte{0x12, 0x34, algorithm, 2}
	if weak {
		sum := sha1.Sum(message)
		data[3] = 1
		data = append(data, sum[:]...)
	} else {
		sum := sha256.Sum256(message)
		data = append(data, sum[:]...)
	}
	return &dnsmessage.UnknownResource{Type: 43, Data: data}
}

func TestDNSSECEarnsNoCredit(t *testing.T) {
	// Two warnings leave room to go up, if signing were to earn anything.
	flawed := func() map[string][]dnsmessage.ResourceBody {
		zone := healthyZone()
		delete(zone, zoneCAA)
		zone[zoneA] = ipv4(10, 0, 0, 1)
		return zone
	}
	unsigned, signed := flawed(), flawed()
	key, data := signedKey(13)
	signed[zoneDNSKEY] = []dnsmessage.ResourceBody{key}
	signed[zoneDS] = []dnsmessage.ResourceBody{dsFor(data, 13, false)}

	for zone, want := range map[*map[string][]dnsmessage.ResourceBody]string{&unsigned: "B", &signed: "B"} {
		d, err := checkDNS(t, &dnsServer{answers: *zone})
		if err != nil {
			t.Fatal(err)
		}
		if got := d.Grades[robertparker.AreaDNS]; got != want {
			t.Errorf("got grade %q, want %q, from %+v", got, want, d.Findings)
		}
		if got := severities(d)["dnssec-status"]; got != robertparker.SeverityInfo {
			t.Errorf("dnssec-status was %q", got)
		}
	}
}

func TestDNSSECProblems(t *testing.T) {
	key, data := signedKey(13)
	oldKey, oldData := signedKey(5)
	other := dsFor([]byte("a different key"), 13, false)
	// A rollover publishes the new DS beside the old one, and that's fine as long as one matches.
	keys := func(k *dnsmessage.UnknownResource) []dnsmessage.ResourceBody { return []dnsmessage.ResourceBody{k} }

	tests := []struct {
		name     string
		ds, keys []dnsmessage.ResourceBody
		check    string
		severity robertparker.Severity
		grade    string
	}{
		{"keys with no DS", nil, keys(key), "dnssec-status", robertparker.SeverityInfo, "A"},
		{"DS with no keys", keys(dsFor(data, 13, false)), nil, "dnssec-chain", robertparker.SeverityFailure, "D"},
		{"DS that matches no key", keys(other), keys(key), "dnssec-chain", robertparker.SeverityFailure, "D"},
		{"one DS of two matches", []dnsmessage.ResourceBody{other, dsFor(data, 13, false)}, keys(key), "dnssec-status", robertparker.SeverityInfo, "A"},
		{"SHA-1 digest", keys(dsFor(data, 13, true)), keys(key), "dnssec-ds-digest", robertparker.SeverityWarning, "A"},
		{"SHA-1 digest beside SHA-256", []dnsmessage.ResourceBody{dsFor(data, 13, true), dsFor(data, 13, false)}, keys(key), "dnssec-status", robertparker.SeverityInfo, "A"},
		{"deprecated algorithm", keys(dsFor(oldData, 5, false)), keys(oldKey), "dnssec-algorithm", robertparker.SeverityWarning, "A"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone := healthyZone()
			zone[zoneDS], zone[zoneDNSKEY] = tt.ds, tt.keys
			d, err := checkDNS(t, &dnsServer{answers: zone})
			if err != nil {
				t.Fatal(err)
			}
			if got := severities(d)[tt.check]; got != tt.severity {
				t.Errorf("%s was %q, want %q, in %+v", tt.check, got, tt.severity, d.Findings)
			}
			if got := d.Grades[robertparker.AreaDNS]; got != tt.grade {
				t.Errorf("got grade %q, want %q, from %+v", got, tt.grade, d.Findings)
			}
		})
	}
}

// A validating resolver answers SERVFAIL for a broken chain, unless told not to check, and then the failure can't be
// told apart from a server that's down.
func TestDNSAsksToSeeBrokenChains(t *testing.T) {
	s := &dnsServer{answers: healthyZone()}
	if _, err := checkDNS(t, s); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.checkingDisabled {
		t.Error("queries didn't disable checking")
	}
}

// The tests above make their own digests, so this is real data, from cloudflare.com, to show they're the right digests.
func TestDNSSECRealKey(t *testing.T) {
	const (
		realKey    = "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="
		realDigest = "32996839A6D808AFE3EB4A795A0E6A7A39A76FC52FF228B22B76F6D63826F2B9"
	)
	publicKey, err := base64.StdEncoding.DecodeString(realKey)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := hex.DecodeString(realDigest)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name     string
		tamper   byte
		severity robertparker.Severity
	}{
		{"as published", 0, ""},
		{"tampered with", 1, robertparker.SeverityFailure},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ds := slices.Clone(digest)
			ds[0] ^= tt.tamper
			s := &dnsServer{answers: map[string][]dnsmessage.ResourceBody{
				"cloudflare.com. TypeNS": nsAt("ns1.example.net."),
				"cloudflare.com. 48":     {&dnsmessage.UnknownResource{Type: 48, Data: append([]byte{1, 1, 3, 13}, publicKey...)}},
				"cloudflare.com. 43":     {&dnsmessage.UnknownResource{Type: 43, Data: append([]byte{0x09, 0x43, 13, 2}, ds...)}},
			}}
			address := startDNS(t, s)
			d := robertparker.NewDomain("cloudflare.com")
			if err := robertparker.DNSAnalyzer(address, nil)(context.Background(), d); err != nil {
				t.Fatal(err)
			}
			if got := severities(d)["dnssec-chain"]; got != tt.severity {
				t.Errorf("got %q, want %q, in %+v", got, tt.severity, d.Findings)
			}
		})
	}
}

func TestDNSNotAZone(t *testing.T) {
	tests := []struct {
		name  string
		zone  map[string][]dnsmessage.ResourceBody
		rcode dnsmessage.RCode
	}{
		{"doesn't exist", nil, dnsmessage.RCodeNameError},
		{"no name servers", map[string][]dnsmessage.ResourceBody{zoneA: ipv4(192, 0, 2, 1)}, dnsmessage.RCodeSuccess},
		// A resolver follows a CNAME, so these NS records would really be the target's.
		{"an alias", map[string][]dnsmessage.ResourceBody{
			zoneNS: append([]dnsmessage.ResourceBody{&dnsmessage.CNAMEResource{CNAME: name("site.host.example.")}}, nsAt("ns1.host.example.")...),
		}, dnsmessage.RCodeSuccess},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := checkDNS(t, &dnsServer{answers: tt.zone, rcode: tt.rcode})
			if err != nil {
				t.Fatal(err)
			}
			if len(d.Grades) != 0 || d.Grade != "" {
				t.Errorf("got grade %q, grades %v", d.Grade, d.Grades)
			}
			if got := severities(d)["dns-zone"]; got != robertparker.SeverityInfo {
				t.Errorf("got %+v", d.Findings)
			}
		})
	}
}

func TestDNSLookupFailureMeansNoGrade(t *testing.T) {
	d, err := checkDNS(t, &dnsServer{rcode: dnsmessage.RCodeServerFailure})
	if err == nil {
		t.Error("no error")
	}
	if got := severities(d)["dns-zone"]; got != robertparker.SeverityUnknown {
		t.Errorf("got %+v", d.Findings)
	}
	if d.Grade != "" || len(d.Grades) != 0 {
		t.Errorf("got grade %q, grades %v", d.Grade, d.Grades)
	}
}

func TestDNSOneFailedTypeMeansNoGrade(t *testing.T) {
	// With an error for anything not in answers, leaving out CAA makes that lookup fail.
	zone := healthyZone()
	delete(zone, zoneCAA)
	for _, key := range []string{zoneAAAA, zoneDS, zoneDNSKEY, "ns2.example.org. TypeAAAA", "mail.example.com. TypeA"} {
		zone[key] = nil
	}
	d, err := checkDNS(t, &dnsServer{answers: zone, rcode: dnsmessage.RCodeServerFailure})
	if err == nil {
		t.Error("no error")
	}
	if got := severities(d)["dns-caa"]; got != robertparker.SeverityUnknown {
		t.Errorf("dns-caa was %q, in %+v", got, d.Findings)
	}
	if got := d.Grades[robertparker.AreaDNS]; got != "" {
		t.Errorf("got grade %q", got)
	}
}

func TestDNSIPv6IsOnlyInformation(t *testing.T) {
	// A failed IPv6 lookup on a name server with an IPv4 address shouldn't stop the domain being graded.
	zone := healthyZone()
	delete(zone, "ns1.example.net. TypeAAAA")
	for _, key := range []string{zoneAAAA, zoneDS, zoneDNSKEY, "ns2.example.org. TypeAAAA", "mail.example.com. TypeA"} {
		zone[key] = nil
	}
	d, err := checkDNS(t, &dnsServer{answers: zone, rcode: dnsmessage.RCodeServerFailure})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Grades[robertparker.AreaDNS]; got != "A" {
		t.Errorf("got grade %q, from %+v", got, d.Findings)
	}
	if _, found := severities(d)["dns-ns-ipv6"]; found {
		t.Errorf("claimed no IPv6, without knowing: %+v", d.Findings)
	}
}

func TestDNSChecksTheRegistrableDomain(t *testing.T) {
	address := startDNS(t, &dnsServer{answers: healthyZone()})
	d := robertparker.NewDomain("mail.example.com")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := robertparker.DNSAnalyzerRouted(address, nil, func(string) string { return address })(ctx, d); err != nil {
		t.Fatal(err)
	}
	if robertparker.Grade(d) != "A" {
		t.Errorf("got %q, from %+v", d.Grade, d.Findings)
	}
}

func TestDNSBareSuffix(t *testing.T) {
	s := &dnsServer{}
	address := startDNS(t, s)
	d := robertparker.NewDomain("com")
	if err := robertparker.DNSAnalyzer(address, nil)(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if queries := s.asked(); len(d.Findings) != 0 || len(queries) != 0 {
		t.Errorf("got %+v after %v", d.Findings, queries)
	}
}

func TestDNSFindingsAreInAStableOrder(t *testing.T) {
	zone := healthyZone()
	key, data := signedKey(1)
	second, secondData := signedKey(5)
	third, _ := signedKey(7)
	zone[zoneDNSKEY] = []dnsmessage.ResourceBody{key, second, third}
	zone[zoneDS] = []dnsmessage.ResourceBody{dsFor(data, 1, false), dsFor(secondData, 5, false)}
	var first string
	for range 20 {
		d, err := checkDNS(t, &dnsServer{answers: zone})
		if err != nil {
			t.Fatal(err)
		}
		var messages []string
		for _, f := range d.Findings {
			messages = append(messages, f.Message)
		}
		got := strings.Join(messages, "\n")
		if first == "" {
			first = got
		}
		if got != first {
			t.Fatalf("order changed:\n%s\n\n%s", got, first)
		}
	}
}

func TestRecordsNullMX(t *testing.T) {
	s := &dnsServer{answers: map[string][]dnsmessage.ResourceBody{
		zoneMX: {&dnsmessage.MXResource{Pref: 0, MX: name(".")}},
	}}
	got, err := collect1(t, s, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records["MX"]) != 1 || got.Records["MX"][0] != "0 ." {
		t.Errorf("got %q", got.Records["MX"])
	}
}
