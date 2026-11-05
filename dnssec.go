package robertparker

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

//DNSSEC validation, done the way a validating resolver does it, so that a mistake is found without depending on one.
//It only says whether signing works. DNSSEC never earns credit, so all this can do to a grade is lower it.

const (
	dnssecAlgorithmRSASHA1      = 5
	dnssecAlgorithmRSASHA1NSEC3 = 7
	dnssecAlgorithmRSASHA256    = 8
	dnssecAlgorithmRSASHA512    = 10
	dnssecAlgorithmP256         = 13
	dnssecAlgorithmP384         = 14
	dnssecAlgorithmEd25519      = 15

	// rrsigFixedSize is how much of an RRSIG record comes before the signer's name.
	rrsigFixedSize = 18

	// rsaMinBits is the smallest key crypto/rsa will use.
	rsaMinBits = 1024

	// signatureExpiryShare says when to warn about a signature: with less than 1/this of its lifetime left.
	signatureExpiryShare = 10
)

// rootAnchors are the root zone's trust anchors, published at https://data.iana.org/root-anchors/root-anchors.xml. A
// validator has to start from something it already trusts, and these need adding to when the root's key changes.
var rootAnchors = []string{
	"20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
	"38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
}

// signature is a parsed RRSIG record.
type signature struct {
	covered               uint16
	algorithm             int
	keyTag                uint16
	originalTTL           uint32
	expiration, inception uint32
	signer                string //The zone it says signed it, in the form zoneName returns.
	signed                []byte //The record up to the signature, with the signer in canonical form, which is signed too.
	value                 []byte
}

// parseRRSIG parses the data of an RRSIG record.
func parseRRSIG(data []byte) (signature, bool) {
	if len(data) <= rrsigFixedSize {
		return signature{}, false
	}
	signer, value, err := readName(data, data[rrsigFixedSize:])
	if err != nil {
		return signature{}, false
	}
	s := signature{
		covered:     binary.BigEndian.Uint16(data),
		algorithm:   int(data[2]),
		originalTTL: binary.BigEndian.Uint32(data[4:]),
		expiration:  binary.BigEndian.Uint32(data[8:]),
		inception:   binary.BigEndian.Uint32(data[12:]),
		keyTag:      binary.BigEndian.Uint16(data[16:]),
		signer:      zoneName(signer),
		value:       value,
	}
	s.signed = append(data[:rrsigFixedSize:rrsigFixedSize], canonicalName(signer)...)
	return s, true
}

// zoneName returns a name in lowercase without its final dot, unless it's the root, which is just a dot.
func zoneName(name string) string {
	if name = strings.ToLower(strings.TrimSuffix(name, ".")); name != "" {
		return name
	}
	return "."
}

// signatureTime returns the time of a 32-bit timestamp, which wraps around, so it's the one nearest to now (RFC 4034
// section 3.1.5).
func signatureTime(timestamp uint32, now time.Time) time.Time {
	return now.Add(time.Duration(int32(timestamp-uint32(now.Unix()))) * time.Second)
}

// rrset is the records of one type at one name, with their signatures, as a validator gets them.
type rrset struct {
	owner      string
	code       dnsmessage.Type
	records    [][]byte //The data of each record, in canonical form.
	signatures []signature
}

// rrsetOf picks one set of records out of answers. It only handles the types it needs to: DS, DNSKEY, and SOA.
func rrsetOf(answers []dnsmessage.Resource, owner string, code dnsmessage.Type) rrset {
	set := rrset{owner: owner, code: code}
	for _, answer := range answers {
		if presentName(answer.Header.Name) != owner {
			continue
		}
		switch body := answer.Body.(type) {
		case *dnsmessage.SOAResource:
			if code == dnsmessage.TypeSOA {
				set.records = append(set.records, soaData(body))
			}
		case *dnsmessage.UnknownResource:
			if body.Type == code {
				set.records = append(set.records, body.Data)
			}
			if s, ok := parseRRSIG(body.Data); ok && body.Type == typeRRSIG && s.covered == uint16(code) {
				set.signatures = append(set.signatures, s)
			}
		}
	}
	return set
}

// soaData returns an SOA record's data in canonical form, which spells out its names in lowercase (RFC 4034 section 6.2).
func soaData(r *dnsmessage.SOAResource) []byte {
	data := append(canonicalName(r.NS.String()), canonicalName(r.MBox.String())...)
	for _, n := range []uint32{r.Serial, r.Refresh, r.Retry, r.Expire, r.MinTTL} {
		data = binary.BigEndian.AppendUint32(data, n)
	}
	return data
}

// signedData returns what sig signs: itself, and then the records in canonical order (RFC 4034 section 3.1.8.1).
func (s *rrset) signedData(sig *signature) []byte {
	records := slices.Clone(s.records)
	slices.SortFunc(records, bytes.Compare)
	records = slices.CompactFunc(records, bytes.Equal)

	owner := canonicalName(s.owner)
	data := slices.Clone(sig.signed)
	for _, record := range records {
		data = append(data, owner...)
		data = binary.BigEndian.AppendUint16(data, uint16(s.code))
		data = binary.BigEndian.AppendUint16(data, uint16(dnsmessage.ClassINET))
		data = binary.BigEndian.AppendUint32(data, sig.originalTTL)
		data = binary.BigEndian.AppendUint16(data, uint16(len(record)))
		data = append(data, record...)
	}
	return data
}

// keys returns the DNSKEY records in the set.
func (s *rrset) keys() []dnskeyRecord {
	var keys []dnskeyRecord
	for _, record := range s.records {
		if len(record) > 4 {
			keys = append(keys, dnskeyRecord{int(binary.BigEndian.Uint16(record)), int(record[3]), record})
		}
	}
	return keys
}

// keyTag returns the number an RRSIG record uses to say which key signed it (RFC 4034 appendix B).
func (k *dnskeyRecord) keyTag() uint16 {
	var sum uint32
	for i, b := range k.data {
		if i%2 == 0 {
			sum += uint32(b) << 8
		} else {
			sum += uint32(b)
		}
	}
	return uint16(sum + sum>>16)
}

// verify reports whether sig is a good signature of message by the key, and whether that could be found out at all.
func (k *dnskeyRecord) verify(sig *signature, message []byte) (good, verifiable bool) {
	key := k.data[4:]
	switch k.algorithm {
	case dnssecAlgorithmRSASHA1, dnssecAlgorithmRSASHA1NSEC3:
		digest := sha1.Sum(message)
		return verifyRSA(key, crypto.SHA1, digest[:], sig.value)
	case dnssecAlgorithmRSASHA256:
		digest := sha256.Sum256(message)
		return verifyRSA(key, crypto.SHA256, digest[:], sig.value)
	case dnssecAlgorithmRSASHA512:
		digest := sha512.Sum512(message)
		return verifyRSA(key, crypto.SHA512, digest[:], sig.value)
	case dnssecAlgorithmP256:
		digest := sha256.Sum256(message)
		return verifyECDSA(elliptic.P256(), key, digest[:], sig.value), true
	case dnssecAlgorithmP384:
		digest := sha512.Sum384(message)
		return verifyECDSA(elliptic.P384(), key, digest[:], sig.value), true
	case dnssecAlgorithmEd25519:
		return len(key) == ed25519.PublicKeySize && ed25519.Verify(key, message, sig.value), true
	}
	return false, false
}

// verifyRSA checks a signature with a key in the format of RFC 3110: the exponent, with its length in front, then the
// modulus.
func verifyRSA(key []byte, hash crypto.Hash, digest, value []byte) (good, verifiable bool) {
	if len(key) < 3 {
		return false, true
	}
	size, start := int(key[0]), 1
	if size == 0 {
		size, start = int(binary.BigEndian.Uint16(key[1:])), 3
	}
	if size == 0 || size > 4 || len(key) <= start+size {
		return false, true
	}
	exponent := new(big.Int).SetBytes(key[start : start+size])
	public := rsa.PublicKey{N: new(big.Int).SetBytes(key[start+size:]), E: int(exponent.Int64())}
	if public.N.BitLen() < rsaMinBits {
		return false, false
	}
	return rsa.VerifyPKCS1v15(&public, hash, digest, value) == nil, true
}

// verifyECDSA checks a signature with a key made of its two coordinates, and a signature made of its two numbers, all
// the same size (RFC 6605).
func verifyECDSA(curve elliptic.Curve, key, digest, value []byte) bool {
	size := curve.Params().BitSize / 8
	if len(key) != 2*size || len(value) != 2*size {
		return false
	}
	public, err := ecdsa.ParseUncompressedPublicKey(curve, append([]byte{4}, key...))
	if err != nil {
		return false
	}
	r, s := new(big.Int).SetBytes(value[:size]), new(big.Int).SetBytes(value[size:])
	return ecdsa.Verify(public, digest, r, s)
}

// signatureState is how a set of records stands up to validation. The higher ones win, since one good signature is all
// that a validator needs.
type signatureState int

const (
	signatureMissing      signatureState = iota //There's no signature from a key that could vouch for it.
	signatureBad                                //There's one, and it doesn't verify.
	signatureNotYetValid                        //It verifies, but its time hasn't come.
	signatureExpired                            //It verifies, but its time has passed.
	signatureUnverifiable                       //It's from a kind of key this can't use.
	signatureValid
)

// validation is the result of validating a set of records.
type validation struct {
	state signatureState
	best  *signature //The signature that gave that result, which for a valid set is the one that lasts longest.
}

// validate checks the signatures on the set against keys, which belong to zone.
func (s *rrset) validate(keys []dnskeyRecord, zone string, now time.Time) validation {
	var result validation
	for i := range s.signatures {
		sig := &s.signatures[i]
		if sig.signer != zone {
			continue
		}
		for j := range keys {
			key := &keys[j]
			if key.flags&dnskeyZoneFlag == 0 || key.algorithm != sig.algorithm || key.keyTag() != sig.keyTag {
				continue
			}
			// The times come first, as they do in a validator, since a signature can be good and still be refused.
			var state signatureState
			switch good, verifiable := key.verify(sig, s.signedData(sig)); {
			case signatureTime(sig.inception, now).After(now):
				state = signatureNotYetValid
			case signatureTime(sig.expiration, now).Before(now):
				state = signatureExpired
			case !verifiable:
				state = signatureUnverifiable
			case good:
				state = signatureValid
			default:
				state = signatureBad
			}
			if state > result.state || state == result.state && result.best != nil && expiresLater(sig, result.best, now) {
				result = validation{state, sig}
			}
		}
	}
	return result
}

// expiresLater reports whether a lasts longer than b.
func expiresLater(a, b *signature, now time.Time) bool {
	return signatureTime(a.expiration, now).After(signatureTime(b.expiration, now))
}

// anchoredKeys returns the keys that a DS record points to.
func anchoredKeys(keys []dnskeyRecord, delegation []dsRecord, zone string) []dnskeyRecord {
	var anchored []dnskeyRecord
	for _, key := range keys {
		if key.flags&dnskeyZoneFlag == 0 {
			continue
		}
		if slices.ContainsFunc(delegation, func(ds dsRecord) bool {
			want := digestDS(ds.digestType, zone, key.data)
			return want != nil && ds.keyTag == key.keyTag() && ds.algorithm == key.algorithm && bytes.Equal(want, ds.digest)
		}) {
			anchored = append(anchored, key)
		}
	}
	return anchored
}

// problem describes a validation that failed, in a sentence about what, or "" if it passed.
func (v validation) problem(what string, now time.Time) string {
	switch v.state {
	case signatureMissing:
		return what + " has no signature from a key that can vouch for it"
	case signatureBad:
		return what + " has a signature that doesn't verify"
	case signatureNotYetValid:
		return fmt.Sprintf("%s has a signature that isn't valid until %s", what, signatureTime(v.best.inception, now).UTC().Format(time.DateTime))
	case signatureExpired:
		return fmt.Sprintf("%s has a signature that expired at %s", what, signatureTime(v.best.expiration, now).UTC().Format(time.DateTime))
	}
	return ""
}

// brokenChain is a link above a zone that a validator wouldn't accept.
type brokenChain struct{ problem string }

func (b *brokenChain) Error() string { return b.problem }

// uncheckedChain is a link above a zone that can't be checked from here, which says nothing about the zone.
type uncheckedChain struct{ reason string }

func (u *uncheckedChain) Error() string { return u.reason }

// trustChain validates zones from the root down, keeping the keys of the zones above, since a list of domains is mostly
// under a few. Only a success is kept, so a brief failure can't affect every domain that follows.
//
// Its queries go through the resolver, since it's what knows where one zone ends and the next begins.
type trustChain struct {
	lookup  *recordLookup
	parents *parentZones
	mu      sync.Mutex
	known   map[string][]dnskeyRecord //Keys that validated, by zone.
}

// delegation validates the DS records of zone, and everything above them, and returns the records.
func (t *trustChain) delegation(ctx context.Context, zone string) ([]dsRecord, error) {
	return t.validateDS(ctx, zone, func(ctx context.Context, zone string) ([]dnskeyRecord, error) {
		t.mu.Lock()
		defer t.mu.Unlock()
		return t.findKeys(ctx, zone)
	})
}

// signedDS gets the DS records of zone. A resolver can hand them over without their signature, as happens with cdc.gov and
// ssa.gov, so if it does, this asks the zone above.
func (t *trustChain) signedDS(ctx context.Context, zone string) (rrset, error) {
	answers, err := t.lookup.signedAnswers(ctx, zone, typeDS)
	if err != nil {
		return rrset{}, err
	}
	set := rrsetOf(answers, zone, typeDS)
	if len(set.signatures) > 0 {
		return set, nil
	}
	parent, err := t.parents.get(ctx, zone)
	if err != nil {
		return set, nil
	}
	for _, address := range parent.servers {
		reply, err := t.lookup.directSigned(ctx, address, zone, typeDS)
		if err != nil {
			continue
		}
		if direct := rrsetOf(reply.answers, zone, typeDS); len(direct.signatures) > 0 {
			return direct, nil
		}
	}
	return set, nil
}

// validateDS validates the DS records of zone, using keysOf to get the keys of the zone above.
func (t *trustChain) validateDS(ctx context.Context, zone string, keysOf func(context.Context, string) ([]dnskeyRecord, error)) ([]dsRecord, error) {
	set, err := t.signedDS(ctx, zone)
	if err != nil {
		return nil, err
	}
	if len(set.records) == 0 {
		return nil, &uncheckedChain{fmt.Sprintf("%s has no DS records, so validators treat what's under it as unsigned.", zone)}
	}
	if len(set.signatures) == 0 {
		return nil, &uncheckedChain{fmt.Sprintf("Got no signature for the DS records of %s, which usually means that the resolver doesn't pass them on, so the zones above weren't checked.", zone)}
	}
	signer := set.signatures[0].signer
	if !isAbove(signer, zone) {
		return nil, &brokenChain{fmt.Sprintf("The DS records of %s are signed by %s, which isn't above it.", zone, signer)}
	}
	keys, err := keysOf(ctx, signer)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	result := set.validate(keys, signer, now)
	if result.state == signatureUnverifiable {
		return nil, &uncheckedChain{fmt.Sprintf("The DS records of %s use a kind of key that can't be checked here.", zone)}
	}
	if problem := result.problem("The DS record set of "+zone, now); problem != "" {
		return nil, &brokenChain{problem + ", so validating resolvers will refuse the domain."}
	}
	delegation := make([]dsRecord, 0, len(set.records))
	for _, record := range set.records {
		if ds, ok := parseDSData(record); ok {
			delegation = append(delegation, ds)
		}
	}
	return delegation, nil
}

// findKeys returns the keys of a zone above the one being checked, once they're validated. It's called with t.mu held.
func (t *trustChain) findKeys(ctx context.Context, zone string) ([]dnskeyRecord, error) {
	if keys, ok := t.known[zone]; ok {
		return keys, nil
	}
	var delegation []dsRecord
	var err error
	if zone == "." {
		delegation = t.anchors()
	} else if delegation, err = t.validateDS(ctx, zone, t.findKeys); err != nil {
		return nil, err
	}
	answers, err := t.lookup.signedAnswers(ctx, zone, typeDNSKEY)
	if err != nil {
		return nil, err
	}
	set := rrsetOf(answers, zone, typeDNSKEY)
	if len(set.signatures) == 0 {
		return nil, &uncheckedChain{fmt.Sprintf("Got no signature for the keys of %s, which usually means that the resolver doesn't pass them on, so the zones above weren't checked.", zone)}
	}
	keys := set.keys()
	anchored := anchoredKeys(keys, delegation, zone)
	if len(anchored) == 0 {
		if zone == "." {
			return nil, &uncheckedChain{"None of the root zone's keys is one that this trusts, so its trust anchors need updating."}
		}
		return nil, &brokenChain{fmt.Sprintf("No DS record of %s matches a key in it, so validating resolvers will refuse the domain.", zone)}
	}
	now := time.Now()
	result := set.validate(anchored, zone, now)
	if result.state == signatureUnverifiable {
		return nil, &uncheckedChain{fmt.Sprintf("The keys of %s are of a kind that can't be checked here.", zone)}
	}
	if problem := result.problem("The key set of "+zone, now); problem != "" {
		return nil, &brokenChain{problem + ", so validating resolvers will refuse the domain."}
	}
	if t.known == nil {
		t.known = map[string][]dnskeyRecord{}
	}
	t.known[zone] = keys
	return keys, nil
}

// anchors returns the trust anchors to start from.
func (t *trustChain) anchors() []dsRecord {
	anchors := t.lookup.anchors
	if anchors == nil {
		anchors = rootAnchors
	}
	var parsed []dsRecord
	for _, s := range anchors {
		if ds, ok := parseDS(s); ok {
			parsed = append(parsed, ds)
		}
	}
	return parsed
}

// isAbove reports whether a zone is above another one.
func isAbove(above, zone string) bool {
	return zone != "." && (above == "." || strings.HasSuffix(zone, "."+above))
}

// parseDSData parses the data of a DS record.
func parseDSData(data []byte) (dsRecord, bool) {
	if len(data) < 4 {
		return dsRecord{}, false
	}
	return dsRecord{binary.BigEndian.Uint16(data), int(data[2]), int(data[3]), data[4:]}, true
}

// checkChain checks everything above the zone, from the root down to its DS records. The zones above aren't the domain's
// doing, but a break there takes it offline all the same.
func (c *dnsChecker) checkChain(ctx context.Context) error {
	_, err := c.chain.delegation(ctx, c.zone)
	var broken *brokenChain
	var unchecked *uncheckedChain
	switch {
	case err == nil:
		return nil
	case errors.As(err, &broken):
		c.add("dnssec-chain", SeverityFailure, rfcDNSSEC, broken.problem)
		return nil
	case errors.As(err, &unchecked):
		c.add("dnssec-chain", SeverityInfo, rfcDNSSEC, unchecked.reason)
		return nil
	}
	c.add("dnssec-chain", SeverityUnknown, rfcDNSSEC, fmt.Sprintf("Couldn't follow the chain of trust to %s: %v", c.zone, err))
	return fmt.Errorf("DNSSEC chain of %s: %w", c.zone, err)
}

// signedZone is what one name server said about the zone's signatures.
type signedZone struct {
	host     string
	answered bool //It's an authority for the zone, and answered both questions.
	keys     rrset
	soa      rrset
}

// askForSignatures asks a name server for the zone's keys and SOA record. Those two show whether the zone's signing
// works: the keys are how the chain enters the zone, and the SOA record changes with the zone, so its signature is as
// fresh as the signing is. A server that doesn't answer is checkDirect's to report.
func (c *dnsChecker) askForSignatures(ctx context.Context, s nameServer) signedZone {
	report := signedZone{host: s.host}
	address := s.ipv4
	if address == "" {
		address = s.ipv6
	}
	keys, err := c.lookup.directSigned(ctx, address, c.zone, typeDNSKEY)
	if err != nil || !keys.header.Authoritative || keys.header.RCode != dnsmessage.RCodeSuccess {
		return report
	}
	soa, err := c.lookup.directSigned(ctx, address, c.zone, dnsmessage.TypeSOA)
	if err != nil || !soa.header.Authoritative || soa.header.RCode != dnsmessage.RCodeSuccess {
		return report
	}
	report.answered = true
	report.keys = rrsetOf(keys.answers, c.zone, typeDNSKEY)
	report.soa = rrsetOf(soa.answers, c.zone, dnsmessage.TypeSOA)
	return report
}

// checkSignatures validates what each name server serves, the way a validating resolver would. It asks each one itself,
// since a server that's stopped getting updates can serve old signatures while the rest are fine, and a resolver would
// hide that for as long as its cache lasted.
//
// A validator that gets a bad answer tries another server, so one bad server costs time, but only if all of them are bad
// is the domain offline.
func (c *dnsChecker) checkSignatures(ctx context.Context, servers []nameServer, delegation []dsRecord) error {
	// IPv6 doesn't work everywhere, and a server that can't be reached from here says nothing.
	if parent, err := c.parents.get(ctx, c.zone); err == nil && !parent.ipv6 {
		servers = slices.DeleteFunc(slices.Clone(servers), func(s nameServer) bool { return s.ipv4 == "" })
	}
	if len(servers) == 0 {
		return nil
	}
	reports := make([]signedZone, len(servers))
	var wait sync.WaitGroup
	for i, server := range servers {
		wait.Go(func() { reports[i] = c.askForSignatures(ctx, server) })
	}
	wait.Wait()

	now := time.Now()
	var hosts []string //Servers that answered.
	var failing []string
	var order []string
	byProblem := map[string][]string{}
	var unverifiable bool
	soonest := map[string]*signature{}
	for i := range reports {
		r := &reports[i]
		if !r.answered {
			continue
		}
		hosts = append(hosts, r.host)
		keys := r.keys.keys()
		checks := []struct {
			what   string
			result validation
		}{
			{"The key set", r.keys.validate(anchoredKeys(keys, delegation, c.zone), c.zone, now)},
			{"The SOA record", r.soa.validate(keys, c.zone, now)},
		}
		bad := false
		for _, check := range checks {
			unverifiable = unverifiable || check.result.state == signatureUnverifiable
			if check.result.state == signatureValid && (soonest[check.what] == nil || expiresLater(soonest[check.what], check.result.best, now)) {
				soonest[check.what] = check.result.best
			}
			problem := check.result.problem(check.what, now)
			if problem == "" {
				continue
			}
			bad = true
			if byProblem[problem] == nil {
				order = append(order, problem)
			}
			byProblem[problem] = append(byProblem[problem], r.host)
		}
		if bad {
			failing = append(failing, r.host)
		}
	}
	if len(hosts) == 0 {
		c.add("dnssec-signature", SeverityUnknown, rfcDNSSEC, "Couldn't get the zone's signatures from its name servers.")
		return fmt.Errorf("no signatures from the name servers of %s", c.zone)
	}
	for _, problem := range order {
		if len(failing) == len(hosts) {
			c.add("dnssec-signature", SeverityFailure, rfcDNSSEC, fmt.Sprintf("%s, so validating resolvers will refuse the domain.", problem))
		} else {
			c.add("dnssec-signature", SeverityWarning, rfcDNSSEC, fmt.Sprintf("%s on %s, so validating resolvers have to try another name server.", problem, strings.Join(byProblem[problem], ", ")))
		}
	}
	if unverifiable {
		c.add("dnssec-signature", SeverityInfo, rfcDNSSEC, "Signed with a kind of key that can't be checked here.")
	}
	for _, what := range []string{"The key set", "The SOA record"} {
		if sig := soonest[what]; sig != nil {
			c.checkExpiry(what, sig, now)
		}
	}
	return nil
}

// checkExpiry warns about a signature that's close to expiring, scaled to its lifetime, since a signer that makes them
// for 11 hours and one that makes them for 70 days replace them at very different times. Of 91 signed zones sampled, the
// signature closest to its end still had 18% of its life left, so a signer that lets one get to 10% has probably stopped.
func (c *dnsChecker) checkExpiry(what string, sig *signature, now time.Time) {
	expires := signatureTime(sig.expiration, now)
	lifetime := expires.Sub(signatureTime(sig.inception, now))
	if expires.Sub(now) < lifetime/signatureExpiryShare {
		c.add("dnssec-expiry", SeverityWarning, rfcDNSSEC, fmt.Sprintf("%s has a signature that expires at %s, with under a tenth of its life left, so signing may have stopped.", what, expires.UTC().Format(time.DateTime)))
	}
}
