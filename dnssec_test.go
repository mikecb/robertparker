package robertparker_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mikecb/robertparker"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	zoneKeyFlag = 0x0100
	entryFlags  = 0x0101 //A zone key that's meant to be the one a DS record points to.
)

// rsaKey is shared, since making one is slow.
var rsaKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

// testKey is a key to sign a made-up zone with.
type testKey struct {
	algorithm byte
	data      []byte //Its DNSKEY record.
	sign      func(message []byte) []byte
}

// newTestKey makes a key of the algorithm. This builds what it needs itself, rather than sharing the code being tested.
func newTestKey(t *testing.T, algorithm byte, flags uint16) *testKey {
	t.Helper()
	k := &testKey{algorithm: algorithm}
	var public []byte
	switch algorithm {
	case 5, 7, 8, 10:
		key := rsaKey()
		public = append([]byte{3, 1, 0, 1}, key.N.Bytes()...)
		hash := crypto.SHA256
		digest := func(m []byte) []byte { sum := sha256.Sum256(m); return sum[:] }
		switch algorithm {
		case 5, 7:
			hash, digest = crypto.SHA1, func(m []byte) []byte { sum := sha1.Sum(m); return sum[:] }
		case 10:
			hash, digest = crypto.SHA512, func(m []byte) []byte { sum := sha512.Sum512(m); return sum[:] }
		}
		k.sign = func(m []byte) []byte {
			value, err := rsa.SignPKCS1v15(nil, key, hash, digest(m))
			if err != nil {
				t.Fatal(err)
			}
			return value
		}
	case 13, 14:
		curve, size := elliptic.P256(), 32
		digest := func(m []byte) []byte { sum := sha256.Sum256(m); return sum[:] }
		if algorithm == 14 {
			curve, size = elliptic.P384(), 48
			digest = func(m []byte) []byte { sum := sha512.Sum384(m); return sum[:] }
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		point, err := key.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		public = point[1:]
		k.sign = func(m []byte) []byte {
			r, s, err := ecdsa.Sign(rand.Reader, key, digest(m))
			if err != nil {
				t.Fatal(err)
			}
			return append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
		}
	case 15:
		var private ed25519.PrivateKey
		var err error
		if public, private, err = ed25519.GenerateKey(rand.Reader); err != nil {
			t.Fatal(err)
		}
		k.sign = func(m []byte) []byte { return ed25519.Sign(private, m) }
	default:
		public = []byte("a kind of key the checks can't use")
		k.sign = func([]byte) []byte { return []byte("a signature that can't be checked") }
	}
	k.data = binary.BigEndian.AppendUint16(nil, flags)
	k.data = append(append(k.data, 3, algorithm), public...)
	return k
}

// keyTag works out a key tag the way RFC 4034 appendix B does.
func keyTag(data []byte) uint16 {
	var sum uint32
	for i, b := range data {
		if i&1 == 1 {
			sum += uint32(b)
		} else {
			sum += uint32(b) << 8
		}
	}
	sum += sum >> 16 & 0xFFFF
	return uint16(sum)
}

func (k *testKey) record() *dnsmessage.UnknownResource {
	return &dnsmessage.UnknownResource{Type: 48, Data: k.data}
}

// ds returns a DS record for the key, in zone.
func (k *testKey) ds(zone string) *dnsmessage.UnknownResource {
	sum := sha256.Sum256(append(wireName(zone), k.data...))
	data := binary.BigEndian.AppendUint16(nil, keyTag(k.data))
	return &dnsmessage.UnknownResource{Type: 43, Data: append(append(data, k.algorithm, 2), sum[:]...)}
}

// wireName returns a name in canonical wire format, for names without escapes.
func wireName(name string) []byte {
	var wire []byte
	for _, label := range strings.Split(strings.ToLower(strings.TrimSuffix(name, ".")), ".") {
		if label != "" {
			wire = append(append(wire, byte(len(label))), label...)
		}
	}
	return append(wire, 0)
}

// timeRange is when a signature holds.
type timeRange struct{ from, until time.Time }

// current is a range that's in the middle of its life.
func current() timeRange {
	return timeRange{time.Now().Add(-10 * 24 * time.Hour), time.Now().Add(10 * 24 * time.Hour)}
}

// expired is a range that's over.
func expired() timeRange {
	return timeRange{time.Now().Add(-20 * 24 * time.Hour), time.Now().Add(-time.Hour)}
}

// rrsig returns an RRSIG record by the key, of records at owner. Its TTL isn't the one the test server sends, since a
// signature covers the TTL the records started with, not what's left of it.
func (k *testKey) rrsig(owner, signer string, code uint16, records [][]byte, when timeRange) *dnsmessage.UnknownResource {
	labels := strings.Count(strings.Trim(owner, "."), ".") + 1
	if strings.Trim(owner, ".") == "" {
		labels = 0
	}
	data := binary.BigEndian.AppendUint16(nil, code)
	data = append(data, k.algorithm, byte(labels))
	data = binary.BigEndian.AppendUint32(data, 3600)
	data = binary.BigEndian.AppendUint32(data, uint32(when.until.Unix()))
	data = binary.BigEndian.AppendUint32(data, uint32(when.from.Unix()))
	data = binary.BigEndian.AppendUint16(data, keyTag(k.data))
	data = append(data, wireName(signer)...)

	message := slices.Clone(data)
	sorted := slices.Clone(records)
	slices.SortFunc(sorted, bytes.Compare)
	for _, record := range sorted {
		message = append(message, wireName(owner)...)
		message = binary.BigEndian.AppendUint16(message, code)
		message = binary.BigEndian.AppendUint16(message, 1)
		message = binary.BigEndian.AppendUint32(message, 3600)
		message = binary.BigEndian.AppendUint16(message, uint16(len(record)))
		message = append(message, record...)
	}
	return &dnsmessage.UnknownResource{Type: 46, Data: append(data, k.sign(message)...)}
}

// soaRecord returns the canonical form of an SOA record.
func soaRecord(body dnsmessage.ResourceBody) []byte {
	r := body.(*dnsmessage.SOAResource)
	data := append(wireName(r.NS.String()), wireName(r.MBox.String())...)
	for _, n := range []uint32{r.Serial, r.Refresh, r.Retry, r.Expire, r.MinTTL} {
		data = binary.BigEndian.AppendUint32(data, n)
	}
	return data
}

// keySet returns DNSKEY records for keys, with the signature of signer.
func keySet(zone string, signer *testKey, when timeRange, keys ...*testKey) []dnsmessage.ResourceBody {
	var bodies []dnsmessage.ResourceBody
	var records [][]byte
	for _, key := range keys {
		bodies = append(bodies, key.record())
		records = append(records, key.data)
	}
	return append(bodies, signer.rrsig(zone, zone, 48, records, when))
}

// signedSOA returns the zone's SOA record with a signature by key.
func signedSOA(zone map[string][]dnsmessage.ResourceBody, key *testKey, when timeRange) []dnsmessage.ResourceBody {
	soa := zone[zoneSOA][0]
	return []dnsmessage.ResourceBody{soa, key.rrsig("example.com.", "example.com.", 6, [][]byte{soaRecord(soa)}, when)}
}

// signZone signs example.com with one key.
func signZone(zone map[string][]dnsmessage.ResourceBody, key *testKey) {
	zone[zoneDNSKEY] = keySet("example.com.", key, current(), key)
	zone[zoneSOA] = signedSOA(zone, key, current())
	zone[zoneDS] = []dnsmessage.ResourceBody{key.ds("example.com.")}
}

func TestDNSSECAlgorithms(t *testing.T) {
	for _, algorithm := range []byte{5, 7, 8, 10, 13, 14, 15} {
		t.Run(fmt.Sprint(algorithm), func(t *testing.T) {
			zone := healthyZone()
			signZone(zone, newTestKey(t, algorithm, entryFlags))
			d, err := checkDNS(t, &dnsServer{answers: zone})
			if err != nil {
				t.Fatal(err)
			}
			if _, found := severities(d)["dnssec-signature"]; found {
				t.Errorf("got %+v", d.Findings)
			}
		})
	}
}

// Real signatures, from each kind of signer, so that a mistake in the code above and in the checks can't cancel out.
func TestDNSSECRealSignatures(t *testing.T) {
	tests := []struct {
		zone  string
		keys  []string
		rrsig string
		at    int64
	}{
		{
			"ed25519.nl",
			[]string{"AQEDD5tTRCy1VUCpeHx1Z/yinXjTtD62Chk9yBm2LHk/F3Cq", "AQADD9rbLWQI4JpQ03j59DVV6wBwSZoPOC6GhVccy5dWp4xi"},
			"ADAPAgAADhBq/jwAauKMgLHLB2VkMjU1MTkCbmwAGGXY90SQ8ETFh1kQdavDT6a/E+YdnoUwKgrD1We+Fx+YrKM6y9n5eM0ntcpZCo1XpkZZYokp8nlS4JAKtDW0DQ==",
			1793911525,
		},
		{
			"knot-dns.cz",
			[]string{"AQADDR3C45L2TPwQ/Y2/XEvnL0XYtMaFF1GNEBMA//boxv6sgOs87RtjdVdI1TMcAHCWf64FYY8AoGDiIgt93hqV7j0=", "AQEDDXNW2Vv9xY8Y+OPpcbuQecxg2jMmg+XoSWpnjcd4YRgQWV8KFvp0uJxgdslJouCuN4P6/Y2jG9H+ad8mt/N1Uao="},
			"ADANAgAABwhq/ClCaumfKtvbCGtub3QtZG5zAmN6ALsjGaRGErKDVVWSVRAU4iur5/jEiMpNrq7+kDP0J6VBGSBT0XMcOXGgrbcD9cbc6a4zujPwfUjWjK3p2ub1kEM=",
			1793911526,
		},
		{
			"dismail.de",
			[]string{
				"AQEDCAMBAAGnDJ4oRNhgRpM4yZLq7sOeaeedvIiwg3w11//7k2wamD3wmoFWVBwwpJDamsfFSJHplA8X/VYi7wjjiLLbBGATA8uiKpwkam+06FRsDK1heZWQnH86rUtu8nIXxqS0xVN89fPrD0mR35tOumG/DUYzO4SapOfg1YrMFalKYxNmf/DD/2GU36G8MSmonMpRuFJvA8a17nDHrOiTjKm/jcV0BwgPceAK73VMq30/AKA+ZZVbTjyhV/+NmTD9EYrl/XVjWoSmtvF6kSEG6qG5dr3BT0NESLH9nbcGWSqZ6lTJ/qGlhaarSv5GSQyqWYWDXeu2g0b++ZX+vXNnd45SIEc3",
				"AQADCAMBAAHLlsDMhKvK2oe+3DiflzvhA0hnKS9gOOPC2EcdPG/XHgKiis4xZLIo5jr0UrHq1j9GDLR5Icz+92LAv2MxbHSYEGflvk3q3OxJ4FXdJfPhNWj56CYJgn95DVSVfVWBoaB8aUyuv6Zvcrv9h9CGC6GsV+T1Sg8ZrQX9s/Z/DBwky9/LCQRGDdZ0/XuKsuAtm80tfBUXOwACMeggF1vLuX4ySUAlvHyG4kQLcx4ZeRd5EtAmFIxyH5HN25Mscmvn4/dnaQaOaezy8yLXlbtaHtl77pMhSR/yhrKtTirqJfC3TFF5VjBJqRVYXZnoI8FWLHoXCrqxAzsFB2nc1+f3MhOr",
			},
			"ADAIAgAADhBq89GpauFWIcZ5B2Rpc21haWwCZGUAkFnbrLP8skhfKGdVJYwKVWhAI2lIJxqhMCIJTIlPLTSIiWsXcL3uUIoiekDAHyYMaOTX5XCOEzsYEE3nzMDL5fflzvLk3T/4oUpMjd6xiLu99o2tDrTiwnvZvOU1t0kxVcPXV9McrzYQqNBKzp1BEjW4ufNXWL0W50UMt7Js8CGAPkDFU72nSj4dg5sUefRNTX95ntoyYmEgqMD8FU+4tAR/uB7bGnZYTY9ynMhTXGavLu5oPxlMhdJELiUZGSdnzF9nRDwdFEjNVmxTEU7306FHwPlRsuKoL+KLclyoCBIl5z+tubU0fOTrqN9cnawsayWQAIl4tXPEB7ch9GbJNQ==",
			1793911527,
		},
	}
	decode := func(s string) []byte {
		data, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	for _, tt := range tests {
		t.Run(tt.zone, func(t *testing.T) {
			var keys [][]byte
			for _, key := range tt.keys {
				keys = append(keys, decode(key))
			}
			at := time.Unix(tt.at, 0)
			if !robertparker.ValidKeySet(tt.zone, keys, decode(tt.rrsig), at) {
				t.Error("the signature didn't validate")
			}
			if robertparker.ValidKeySet(tt.zone, keys, decode(tt.rrsig), at.Add(365*24*time.Hour)) {
				t.Error("the signature validated after it expired")
			}
			keys[0][len(keys[0])-1] ^= 1
			if robertparker.ValidKeySet(tt.zone, keys, decode(tt.rrsig), at) {
				t.Error("the signature validated with a key changed")
			}
		})
	}
}

func TestDNSSECSignatures(t *testing.T) {
	type zoneMap = map[string][]dnsmessage.ResourceBody
	tests := []struct {
		name     string
		change   func(zone zoneMap, key, other *testKey)
		check    string
		severity robertparker.Severity
		grade    string
	}{
		{"nothing wrong", func(zoneMap, *testKey, *testKey) {}, "", "", "A"},
		{"expired key set", func(zone zoneMap, key, _ *testKey) {
			zone[zoneDNSKEY] = keySet("example.com.", key, expired(), key)
		}, "dnssec-signature", robertparker.SeverityFailure, "D"},
		{"expired SOA", func(zone zoneMap, key, _ *testKey) {
			zone[zoneSOA] = signedSOA(zone, key, expired())
		}, "dnssec-signature", robertparker.SeverityFailure, "D"},
		{"not valid yet", func(zone zoneMap, key, _ *testKey) {
			zone[zoneSOA] = signedSOA(zone, key, timeRange{time.Now().Add(time.Hour), time.Now().Add(2 * time.Hour)})
		}, "dnssec-signature", robertparker.SeverityFailure, "D"},
		{"changed after signing", func(zone zoneMap, _, _ *testKey) {
			zone[zoneSOA][0] = soaWith(7200, 900, 1209600, 1800)[0]
		}, "dnssec-signature", robertparker.SeverityFailure, "D"},
		{"no signature on the SOA", func(zone zoneMap, _, _ *testKey) {
			zone[zoneSOA] = zone[zoneSOA][:1]
		}, "dnssec-signature", robertparker.SeverityFailure, "D"},
		{"no signature on the keys", func(zone zoneMap, _, _ *testKey) {
			zone[zoneDNSKEY] = zone[zoneDNSKEY][:1]
		}, "dnssec-signature", robertparker.SeverityFailure, "D"},
		{"SOA signed by a key that isn't in the zone", func(zone zoneMap, _, other *testKey) {
			zone[zoneSOA] = signedSOA(zone, other, current())
		}, "dnssec-signature", robertparker.SeverityFailure, "D"},
		{"keys signed only by a key with no DS", func(zone zoneMap, key, other *testKey) {
			zone[zoneDNSKEY] = keySet("example.com.", other, current(), key, other)
		}, "dnssec-signature", robertparker.SeverityFailure, "D"},
		{"SOA signed by the second key of two", func(zone zoneMap, key, other *testKey) {
			zone[zoneDNSKEY] = keySet("example.com.", key, current(), key, other)
			zone[zoneSOA] = signedSOA(zone, other, current())
		}, "", "", "A"},
		{"an expired signature beside a good one", func(zone zoneMap, key, _ *testKey) {
			zone[zoneSOA] = append(zone[zoneSOA], signedSOA(zone, key, expired())[1])
		}, "", "", "A"},
		{"names in capitals", func(zone zoneMap, key, _ *testKey) {
			soa := *zone[zoneSOA][0].(*dnsmessage.SOAResource)
			soa.NS, soa.MBox = name("NS1.Example.NET."), name("Admin.Example.NET.")
			zone[zoneSOA] = []dnsmessage.ResourceBody{&soa}
			zone[zoneSOA] = signedSOA(zone, key, current())
		}, "", "", "A"},
		{"signature close to its end", func(zone zoneMap, key, _ *testKey) {
			zone[zoneSOA] = signedSOA(zone, key, timeRange{time.Now().Add(-20 * time.Hour), time.Now().Add(time.Hour)})
		}, "dnssec-expiry", robertparker.SeverityWarning, "A"},
		{"short signature with hours left", func(zone zoneMap, key, _ *testKey) {
			zone[zoneSOA] = signedSOA(zone, key, timeRange{time.Now().Add(-5 * time.Hour), time.Now().Add(6 * time.Hour)})
		}, "", "", "A"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, other := newTestKey(t, 13, entryFlags), newTestKey(t, 13, zoneKeyFlag)
			zone := healthyZone()
			signZone(zone, key)
			tt.change(zone, key, other)
			d, err := checkDNS(t, &dnsServer{answers: zone})
			if err != nil {
				t.Fatal(err)
			}
			found := severities(d)
			if tt.check != "" && found[tt.check] != tt.severity {
				t.Errorf("%s was %q, want %q, in %+v", tt.check, found[tt.check], tt.severity, d.Findings)
			}
			if tt.check == "" {
				for _, check := range []string{"dnssec-signature", "dnssec-expiry"} {
					if _, ok := found[check]; ok {
						t.Errorf("got %s, in %+v", check, d.Findings)
					}
				}
			}
			if got := d.Grades[robertparker.AreaDNS]; got != tt.grade {
				t.Errorf("got grade %q, want %q, from %+v", got, tt.grade, d.Findings)
			}
		})
	}
}

func TestDNSSECKeysThatCantBeChecked(t *testing.T) {
	zone := healthyZone()
	signZone(zone, newTestKey(t, 16, entryFlags))
	d, err := checkDNS(t, &dnsServer{answers: zone})
	if err != nil {
		t.Fatal(err)
	}
	if got := severities(d)["dnssec-signature"]; got != robertparker.SeverityInfo {
		t.Errorf("got %q, in %+v", got, d.Findings)
	}
	if got := d.Grades[robertparker.AreaDNS]; got != "A" {
		t.Errorf("got grade %q", got)
	}
}

// One server with old signatures is what a resolver's cache hides, so each one is asked.
func TestDNSSECEachNameServerIsChecked(t *testing.T) {
	key := newTestKey(t, 13, entryFlags)
	zone := healthyZone()
	signZone(zone, key)
	stale := signedSOA(zone, key, expired())
	serve := func(s *dnsServer, soa []dnsmessage.ResourceBody) {
		s.answers[zoneDNSKEY], s.answers[zoneSOA] = zone[zoneDNSKEY], soa
	}

	t.Run("one is stale", func(t *testing.T) {
		n := healthyInternet()
		serve(n[ns1v4], zone[zoneSOA])
		serve(n[ns2v4], stale)
		d, err := checkZone(t, zone, n)
		if err != nil {
			t.Fatal(err)
		}
		if got := severities(d)["dnssec-signature"]; got != robertparker.SeverityWarning {
			t.Errorf("got %q, in %+v", got, d.Findings)
		}
		if got := messages(d, "dnssec-signature"); !strings.Contains(got, "ns2.example.org") || strings.Contains(got, "ns1.example.net") {
			t.Errorf("got %q", got)
		}
	})
	t.Run("all are stale", func(t *testing.T) {
		n := healthyInternet()
		serve(n[ns1v4], stale)
		serve(n[ns2v4], stale)
		d, err := checkZone(t, zone, n)
		if err != nil {
			t.Fatal(err)
		}
		if got := severities(d)["dnssec-signature"]; got != robertparker.SeverityFailure {
			t.Errorf("got %q, in %+v", got, d.Findings)
		}
	})
	t.Run("one has no signatures", func(t *testing.T) {
		n := healthyInternet()
		serve(n[ns1v4], zone[zoneSOA])
		serve(n[ns2v4], zone[zoneSOA][:1])
		d, err := checkZone(t, zone, n)
		if err != nil {
			t.Fatal(err)
		}
		if got := severities(d)["dnssec-signature"]; got != robertparker.SeverityWarning {
			t.Errorf("got %q, in %+v", got, d.Findings)
		}
	})
	t.Run("one doesn't answer", func(t *testing.T) {
		t.Parallel()
		n := healthyInternet()
		serve(n[ns1v4], zone[zoneSOA])
		delete(n, ns2v4)
		d, err := checkZone(t, zone, n)
		if err != nil {
			t.Fatal(err)
		}
		if _, found := severities(d)["dnssec-signature"]; found {
			t.Errorf("got %+v", d.Findings)
		}
	})
	t.Run("none answers", func(t *testing.T) {
		t.Parallel()
		n := healthyInternet()
		delete(n, ns1v4)
		delete(n, ns2v4)
		d, err := checkZone(t, zone, n)
		if err == nil {
			t.Error("got no error")
		}
		if got := severities(d)["dnssec-signature"]; got != robertparker.SeverityUnknown {
			t.Errorf("got %q, in %+v", got, d.Findings)
		}
		if d.Grades[robertparker.AreaDNS] != "" {
			t.Errorf("got grades %v", d.Grades)
		}
	})
}

// A server that can't be reached from here says nothing about the zone.
func TestDNSSECSkipsServersOutOfReach(t *testing.T) {
	zone := healthyZone()
	signZone(zone, newTestKey(t, 13, entryFlags))
	zone[zoneNS] = nsAt("ns1.example.net.")
	delete(zone, "ns1.example.net. TypeA")
	n := healthyInternet()
	delete(n, parentv6)
	delete(n, ns1v6)
	d, _ := checkZone(t, zone, n) // There's an error, from the other checks that can't reach it.
	if _, found := severities(d)["dnssec-signature"]; found {
		t.Errorf("got %+v", d.Findings)
	}
}

// signedTree is example.com signed all the way from a made-up root.
type signedTree struct {
	root, com, key *testKey
	answers        map[string][]dnsmessage.ResourceBody
	anchors        []string
}

func newTree(t *testing.T) *signedTree {
	tree := &signedTree{
		root:    newTestKey(t, 13, entryFlags),
		com:     newTestKey(t, 13, entryFlags),
		key:     newTestKey(t, 13, entryFlags),
		answers: healthyZone(),
	}
	signZone(tree.answers, tree.key)
	tree.answers[zoneDS] = tree.delegation("example.com.", "com.", tree.com, tree.key, current())
	tree.answers["com. 43"] = tree.delegation("com.", ".", tree.root, tree.com, current())
	tree.answers["com. 48"] = keySet("com.", tree.com, current(), tree.com)
	tree.answers[". 48"] = keySet(".", tree.root, current(), tree.root)
	root := tree.root.ds(".").Data
	tree.anchors = []string{fmt.Sprintf("%d %d %d %s", keyTag(tree.root.data), root[2], root[3], hex.EncodeToString(root[4:]))}
	return tree
}

// delegation returns the DS record of owner, for key, signed by the zone above.
func (*signedTree) delegation(owner, above string, signer, key *testKey, when timeRange) []dnsmessage.ResourceBody {
	ds := key.ds(owner)
	return []dnsmessage.ResourceBody{ds, signer.rrsig(owner, above, 43, [][]byte{ds.Data}, when)}
}

func (tree *signedTree) check(t *testing.T, n internet) (*robertparker.Domain, error) {
	t.Helper()
	resolver := &dnsServer{answers: tree.answers}
	address := startDNS(t, resolver)
	rewrite := func(string) string { return address }
	if n != nil {
		rewrite, _ = n.route(t)
	}
	d := robertparker.NewDomain("example.com")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := robertparker.DNSAnalyzerAnchored(address, rewrite, tree.anchors)(ctx, d)
	robertparker.Grade(d)
	return d, err
}

func TestDNSSECChain(t *testing.T) {
	tests := []struct {
		name     string
		change   func(tree *signedTree)
		severity robertparker.Severity
		message  string
	}{
		{"whole chain", func(*signedTree) {}, "", ""},
		{"expired signature on the zone's DS records", func(tree *signedTree) {
			tree.answers[zoneDS] = tree.delegation("example.com.", "com.", tree.com, tree.key, expired())
		}, robertparker.SeverityFailure, "The DS record set of example.com has a signature that expired"},
		{"zone's DS records signed by an unknown key", func(tree *signedTree) {
			tree.answers[zoneDS] = tree.delegation("example.com.", "com.", tree.key, tree.key, current())
		}, robertparker.SeverityFailure, "no signature from a key"},
		{"DS records signed by a zone not above it", func(tree *signedTree) {
			tree.answers[zoneDS] = tree.delegation("example.com.", "example.org.", tree.com, tree.key, current())
		}, robertparker.SeverityFailure, "isn't above it"},
		{"expired signature on the keys above", func(tree *signedTree) {
			tree.answers["com. 48"] = keySet("com.", tree.com, expired(), tree.com)
		}, robertparker.SeverityFailure, "The key set of com has a signature that expired"},
		{"keys above that don't match their DS records", func(tree *signedTree) {
			tree.answers["com. 43"] = tree.delegation("com.", ".", tree.root, tree.root, current())
		}, robertparker.SeverityFailure, "No DS record of com matches"},
		{"root that isn't trusted", func(tree *signedTree) {
			tree.anchors = []string{"20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"}
		}, robertparker.SeverityInfo, "trust anchors need updating"},
		{"no signatures from the resolver", func(tree *signedTree) {
			tree.answers[zoneDS] = tree.answers[zoneDS][:1]
		}, robertparker.SeverityInfo, "doesn't pass them on"},
		{"nothing above the zone is signed", func(tree *signedTree) {
			delete(tree.answers, "com. 43")
		}, robertparker.SeverityInfo, "treat what's under it as unsigned"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := newTree(t)
			tt.change(tree)
			d, err := tree.check(t, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := severities(d)["dnssec-chain"]; got != tt.severity {
				t.Errorf("got %q, want %q, in %+v", got, tt.severity, d.Findings)
			}
			if got := messages(d, "dnssec-chain"); !strings.Contains(got, tt.message) {
				t.Errorf("got %q, want %q", got, tt.message)
			}
		})
	}
}

// A resolver can hand over DS records without their signature, as happens with cdc.gov, so the parent is asked.
func TestDNSSECChainAsksTheParentForSignatures(t *testing.T) {
	tree := newTree(t)
	n := healthyInternet()
	for _, s := range []*dnsServer{n[ns1v4], n[ns2v4]} {
		s.answers[zoneDNSKEY], s.answers[zoneSOA] = tree.answers[zoneDNSKEY], tree.answers[zoneSOA]
	}
	n[parentv4].answers = map[string][]dnsmessage.ResourceBody{zoneDS: tree.answers[zoneDS]}
	tree.answers[zoneDS] = tree.answers[zoneDS][:1]
	d, err := tree.check(t, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := severities(d)["dnssec-chain"]; found {
		t.Errorf("got %+v", d.Findings)
	}
}

func TestDNSSECChainLookupFailureMeansNoGrade(t *testing.T) {
	tree := newTree(t)
	delete(tree.answers, ". 48")
	s := &dnsServer{answers: tree.answers, rcode: dnsmessage.RCodeServerFailure}
	address := startDNS(t, s)
	d := robertparker.NewDomain("example.com")
	err := robertparker.DNSAnalyzerAnchored(address, func(string) string { return address }, tree.anchors)(context.Background(), d)
	if err == nil {
		t.Error("got no error")
	}
	if got := severities(d)["dnssec-chain"]; got != robertparker.SeverityUnknown {
		t.Errorf("got %q, in %+v", got, d.Findings)
	}
}

// The zones above are the same for most of a list, so each one's keys are only fetched once.
func TestDNSSECChainIsKept(t *testing.T) {
	tree := newTree(t)
	s := &dnsServer{answers: tree.answers}
	address := startDNS(t, s)
	analyze := robertparker.DNSAnalyzerAnchored(address, func(string) string { return address }, tree.anchors)
	for range 2 {
		if err := analyze(context.Background(), robertparker.NewDomain("example.com")); err != nil {
			t.Fatal(err)
		}
	}
	count := 0
	for _, query := range s.asked() {
		if query == ". 48" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("asked for the root's keys %d times", count)
	}
}

func TestCanonicalName(t *testing.T) {
	tests := []struct {
		name string
		want []byte
	}{
		{"", []byte{0}},
		{".", []byte{0}},
		{"com", []byte("\x03com\x00")},
		{"Example.COM.", []byte("\x07example\x03com\x00")},
		{`first\.Last.example.`, []byte("\x0afirst.last\x07example\x00")},
		{`back\\slash.`, []byte("\x0aback\\slash\x00")},
		{"caf\xc3\x89.example", []byte("\x05caf\xc3\x89\x07example\x00")},
	}
	for _, tt := range tests {
		if got := robertparker.CanonicalName(tt.name); !bytes.Equal(got, tt.want) {
			t.Errorf("CanonicalName(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}
