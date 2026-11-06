package robertparker

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

//DNS checks. These read a domain's records through a resolver, so they see what everyone else sees, but they don't ask
//its name servers anything directly. That rules out comparing the name servers with each other or with the parent zone.

const (
	// AreaDNS is the area of the DNS checks, DNSSEC included.
	AreaDNS = "dns"

	rfcDNSServers = "RFC 2182"
	rfcDNSNames   = "RFC 2181"
	rfcSOA        = "RFC 1912"
	rfcCAA        = "RFC 8659"
	rfcDNSSEC     = "RFC 4034"
	rfcDNSSECAlgs = "RFC 9904"

	// The ranges RFC 1912 suggests for SOA timers, in seconds. Half of the large sites sampled are outside them, so being
	// outside is only information. RFC 2308 replaced its advice on the minimum, which is now how long a "no such name"
	// answer is cached, with one to three hours.
	soaMinRefresh  = 1200
	soaMaxRefresh  = 43200
	soaMinExpire   = 1209600
	soaMaxExpire   = 2419200
	soaMaxNegative = 3 * 3600

	dnskeyZoneFlag = 0x0100 //Marks a DNSKEY as a zone key, the only kind a DS record can point to (RFC 4034 section 2.1.1).

	digestSHA1   = 1
	digestSHA256 = 2
	digestSHA384 = 4
)

// deprecatedDNSSECAlgorithms are the signing algorithms to stop using, by number.
var deprecatedDNSSECAlgorithms = map[int]string{
	1:  "RSA/MD5",
	3:  "DSA/SHA-1",
	5:  "RSA/SHA-1",
	6:  "DSA-NSEC3-SHA1",
	7:  "RSASHA1-NSEC3-SHA1",
	12: "ECC-GOST",
}

// caaTags are the CAA properties a CA can be expected to understand. One it doesn't, marked critical, stops it issuing.
var caaTags = []string{"issue", "issuewild", "iodef", "contactemail", "contactphone", "issuemail", "issuevmc"}

// DNSAnalyzer returns an Analyzer that checks the records of a domain's zone, and adds Findings. It checks the registrable
// domain, since that's where the zone starts, not any subdomain that was given. server is the DNS server to ask, as host
// or host:port, and if it's empty, the system's is used. Every query goes through limiter, which can be nil. A lookup that
// fails adds a SeverityUnknown finding and returns an error, so that a network problem is never reported as a missing
// record.
//
// DNSSEC is tested, but never earns credit. A zone gets the same grade signed or unsigned, and only loses marks for
// signing that's broken or weak, since a mistake there takes the whole domain offline.
func DNSAnalyzer(server string, limiter *Limiter) Analyzer {
	return newDNSAnalyzer(&recordLookup{server: server, limiter: limiter})
}

// newDNSAnalyzer returns a DNSAnalyzer that uses lookup.
func newDNSAnalyzer(lookup *recordLookup) Analyzer {
	parents := &parentZones{lookup: lookup}
	chain := &trustChain{lookup: lookup, parents: parents}
	return func(ctx context.Context, d *Domain) error {
		zone := d.registrable()
		if zone == "" {
			return nil
		}
		c := dnsChecker{lookup: lookup, parents: parents, chain: chain, domain: d, zone: zone}
		return c.check(ctx)
	}
}

// dnsChecker is the state of checking one domain.
type dnsChecker struct {
	lookup  *recordLookup
	parents *parentZones
	chain   *trustChain
	domain  *Domain
	zone    string
}

// add records a finding about the domain's DNS.
func (c *dnsChecker) add(check string, severity Severity, standard, message string) {
	c.domain.addFinding(AreaDNS, check, severity, standard, message)
}

// get returns the records of one type at name. Finding none isn't an error, but a failed lookup is, and adds a finding
// for check.
func (c *dnsChecker) get(ctx context.Context, check, standard, name string, code dnsmessage.Type) ([]string, error) {
	values, err := c.lookup.lookup(ctx, name, code)
	if err != nil {
		c.add(check, SeverityUnknown, standard, fmt.Sprintf("Couldn't look up the records of %s: %v", name, err))
		return nil, fmt.Errorf("DNS lookup of %s: %w", name, err)
	}
	return values, nil
}

// check runs the checks. A name that isn't a zone of its own, like a site on a hosting provider's domain, isn't graded,
// since it has no delegation of its own to judge. A CNAME rules a zone out, since a resolver follows it, and the NS
// records in the answer are its target's.
func (c *dnsChecker) check(ctx context.Context) error {
	answers, err := c.lookup.answers(ctx, c.zone, dnsmessage.TypeNS)
	if err != nil {
		c.domain.Checked(AreaDNS)
		c.add("dns-zone", SeverityUnknown, "", fmt.Sprintf("Couldn't look up the name servers of %s: %v", c.zone, err))
		return fmt.Errorf("DNS lookup: %w", err)
	}
	nameServers := presentAnswers(answers, dnsmessage.TypeNS)
	if isAlias(answers, c.zone) || len(nameServers) == 0 {
		c.add("dns-zone", SeverityInfo, "", fmt.Sprintf("%s has no name servers of its own, so its DNS wasn't graded.", c.zone))
		return nil
	}
	c.domain.Checked(AreaDNS)
	servers, err := c.checkNameServers(ctx, nameServers)
	return errors.Join(
		err,
		c.checkSOA(ctx),
		c.checkAddresses(ctx),
		c.checkMX(ctx),
		c.checkCAA(ctx),
		c.checkDangling(ctx),
		c.checkDNSSEC(ctx, servers),
		c.checkDirect(ctx, servers), // Last, since a server that doesn't reply is what takes the longest.
	)
}

// checkNameServers checks that the name servers resolve, and that one failure can't take them all down. It returns the
// ones that can be reached from the internet.
func (c *dnsChecker) checkNameServers(ctx context.Context, hosts []string) ([]nameServer, error) {
	if len(hosts) == 1 {
		c.add("dns-ns-count", SeverityWarning, rfcDNSServers, fmt.Sprintf("Only one name server, %s, so there's no backup if it fails.", hosts[0]))
	}
	var errs []error
	var servers []nameServer
	networks := map[netip.Prefix]bool{}
	compared := 0 //Name servers with IPv4 addresses, the ones networks can be compared for.
	ipv6, known := false, true
	for _, host := range hosts {
		answers, err := c.lookup.answers(ctx, host, dnsmessage.TypeA)
		if err != nil {
			c.add("dns-ns-resolve", SeverityUnknown, rfcDNSServers, fmt.Sprintf("Couldn't look up the addresses of %s: %v", host, err))
			errs = append(errs, fmt.Errorf("DNS lookup of %s: %w", host, err))
			known = false
			continue
		}
		if isAlias(answers, host) {
			c.add("dns-ns-cname", SeverityWarning, rfcDNSNames, fmt.Sprintf("Name server %s is a CNAME, which isn't allowed.", host))
		}
		ipv4 := presentAnswers(answers, dnsmessage.TypeA)
		// IPv6 is only information, unless there's no IPv4 address to fall back on.
		addresses, err := c.lookup.lookup(ctx, host, dnsmessage.TypeAAAA)
		switch {
		case err != nil && len(ipv4) == 0:
			c.add("dns-ns-resolve", SeverityUnknown, rfcDNSServers, fmt.Sprintf("Couldn't look up the addresses of %s: %v", host, err))
			errs = append(errs, fmt.Errorf("DNS lookup of %s: %w", host, err))
			known = false
			continue
		case err != nil:
			known = false
		case len(addresses) > 0:
			ipv6 = true
		}
		if len(ipv4) == 0 && len(addresses) == 0 {
			c.add("dns-ns-resolve", SeverityFailure, rfcDNSServers, fmt.Sprintf("Name server %s doesn't resolve to an address.", host))
		}
		server := nameServer{host: host, ipv4: firstPublic(ipv4), ipv6: firstPublic(addresses)}
		if server.ipv4 != "" || server.ipv6 != "" {
			servers = append(servers, server)
		} else if len(ipv4) > 0 || len(addresses) > 0 {
			c.add("dns-ns-resolve", SeverityFailure, rfcDNSServers, fmt.Sprintf("Name server %s only has addresses that can't be reached from the internet.", host))
		}
		if len(ipv4) > 0 {
			compared++
		}
		for _, s := range ipv4 {
			if address, err := netip.ParseAddr(s); err == nil {
				if network, err := address.Prefix(24); err == nil {
					networks[network] = true
				}
			}
		}
	}
	// A /24 is a rough stand-in for a network, but sharing one is a clear sign of sharing everything else.
	if compared > 1 && len(networks) == 1 {
		c.add("dns-ns-network", SeverityWarning, rfcDNSServers, "All the name servers are on one /24 network, so one outage could take them all down.")
	}
	if known && !ipv6 {
		c.add("dns-ns-ipv6", SeverityInfo, "", "None of the name servers has an IPv6 address.")
	}
	return servers, errors.Join(errs...)
}

// checkSOA checks that the SOA record exists, and that its timers make sense. Timers that contradict each other cost
// a warning, but being outside the suggested ranges doesn't, since secondary servers mostly don't use them any more.
func (c *dnsChecker) checkSOA(ctx context.Context) error {
	records, err := c.get(ctx, "dns-soa", rfcSOA, c.zone, dnsmessage.TypeSOA)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		c.add("dns-soa", SeverityFailure, rfcSOA, "No SOA record, which every zone must have.")
		return nil
	}
	fields := strings.Fields(records[0])
	if len(fields) != 7 {
		return nil
	}
	var timers [4]uint64
	for i := range timers {
		if timers[i], err = strconv.ParseUint(fields[3+i], 10, 32); err != nil {
			return nil
		}
	}
	refresh, retry, expire, negative := timers[0], timers[1], timers[2], timers[3]
	if retry > refresh {
		c.add("dns-soa-timers", SeverityWarning, rfcSOA, fmt.Sprintf("SOA retry (%ds) is longer than refresh (%ds).", retry, refresh))
	}
	if expire < refresh+retry {
		c.add("dns-soa-timers", SeverityWarning, rfcSOA, fmt.Sprintf("SOA expire (%ds) is shorter than refresh and retry together (%ds), so secondaries can drop the zone before they retry.", expire, refresh+retry))
	}
	var outside []string
	if refresh < soaMinRefresh || refresh > soaMaxRefresh {
		outside = append(outside, fmt.Sprintf("refresh %ds", refresh))
	}
	if expire < soaMinExpire || expire > soaMaxExpire {
		outside = append(outside, fmt.Sprintf("expire %ds", expire))
	}
	if negative > soaMaxNegative {
		outside = append(outside, fmt.Sprintf("negative caching %ds", negative))
	}
	if len(outside) > 0 {
		c.add("dns-soa-timers", SeverityInfo, rfcSOA, fmt.Sprintf("SOA timers are outside the suggested ranges: %s.", strings.Join(outside, ", ")))
	}
	return nil
}

// checkAddresses checks that the domain doesn't publish addresses that can't be reached from the internet, which at best
// is a mistake, and at worst sends visitors to something on their own network.
func (c *dnsChecker) checkAddresses(ctx context.Context) error {
	var errs []error
	for _, code := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		records, err := c.get(ctx, "dns-address", "RFC 6890", c.zone, code)
		errs = append(errs, err)
		for _, s := range records {
			if address, err := netip.ParseAddr(s); err == nil && internalAddress(address) {
				c.add("dns-address", SeverityWarning, "RFC 6890", fmt.Sprintf("Publishes the address %s, which can't be reached from the internet.", s))
			}
		}
	}
	return errors.Join(errs...)
}

// checkMX checks that the mail servers aren't CNAMEs, by asking for their addresses, since a resolver includes any CNAME
// it followed. Asking for the CNAME itself is no good: Exchange Online's servers fail those queries. The email checks
// cover whether the mail servers resolve.
func (c *dnsChecker) checkMX(ctx context.Context) error {
	records, err := c.get(ctx, "dns-mx-cname", rfcDNSNames, c.zone, dnsmessage.TypeMX)
	if err != nil {
		return err
	}
	var errs []error
	for _, record := range records {
		_, host, found := strings.Cut(record, " ")
		if !found || host == "." {
			continue
		}
		answers, err := c.lookup.answers(ctx, host, dnsmessage.TypeA)
		if err != nil {
			c.add("dns-mx-cname", SeverityUnknown, rfcDNSNames, fmt.Sprintf("Couldn't look up %s: %v", host, err))
			errs = append(errs, fmt.Errorf("DNS lookup of %s: %w", host, err))
			continue
		}
		if isAlias(answers, host) {
			c.add("dns-mx-cname", SeverityWarning, rfcDNSNames, fmt.Sprintf("Mail server %s is a CNAME, which isn't allowed.", host))
		}
	}
	return errors.Join(errs...)
}

// checkCAA checks that CAA records limit which CAs can issue certificates, without stopping them all by accident.
func (c *dnsChecker) checkCAA(ctx context.Context) error {
	records, err := c.get(ctx, "dns-caa", rfcCAA, c.zone, typeCAA)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		c.add("dns-caa", SeverityWarning, rfcCAA, "No CAA records, so any CA can issue certificates for this domain.")
		return nil
	}
	restricted := false
	for _, record := range records {
		fields := strings.SplitN(record, " ", 3)
		if len(fields) != 3 {
			continue
		}
		flags, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		tag := strings.ToLower(fields[1])
		restricted = restricted || tag == "issue"
		if flags&128 != 0 && !slices.Contains(caaTags, tag) {
			c.add("dns-caa-critical", SeverityFailure, rfcCAA, fmt.Sprintf("CAA property %q is marked critical, and CAs that don't know it must refuse to issue.", fields[1]))
		}
	}
	if !restricted {
		c.add("dns-caa", SeverityWarning, rfcCAA, "CAA records don't include an issue property, so they don't limit who can issue ordinary certificates.")
	}
	return nil
}

// dsRecord is a parsed DS record.
type dsRecord struct {
	keyTag                uint16
	algorithm, digestType int
	digest                []byte
}

// parseDS parses a DS record in presentation format.
func parseDS(s string) (dsRecord, bool) {
	fields := strings.Fields(s)
	if len(fields) != 4 {
		return dsRecord{}, false
	}
	keyTag, err := strconv.ParseUint(fields[0], 10, 16)
	algorithm, err2 := strconv.Atoi(fields[1])
	digestType, err3 := strconv.Atoi(fields[2])
	digest, err4 := hex.DecodeString(fields[3])
	if err != nil || err2 != nil || err3 != nil || err4 != nil {
		return dsRecord{}, false
	}
	return dsRecord{uint16(keyTag), algorithm, digestType, digest}, true
}

// dnskeyRecord is a parsed DNSKEY record.
type dnskeyRecord struct {
	flags, algorithm int
	data             []byte //The record as it's sent, which is what a DS record's digest covers.
}

// parseDNSKEY parses a DNSKEY record in presentation format.
func parseDNSKEY(s string) (dnskeyRecord, bool) {
	fields := strings.Fields(s)
	if len(fields) != 4 {
		return dnskeyRecord{}, false
	}
	flags, err := strconv.ParseUint(fields[0], 10, 16)
	protocol, err2 := strconv.ParseUint(fields[1], 10, 8)
	algorithm, err3 := strconv.ParseUint(fields[2], 10, 8)
	key, err4 := base64.StdEncoding.DecodeString(fields[3])
	if err != nil || err2 != nil || err3 != nil || err4 != nil {
		return dnskeyRecord{}, false
	}
	data := binary.BigEndian.AppendUint16(nil, uint16(flags))
	data = append(data, byte(protocol), byte(algorithm))
	return dnskeyRecord{int(flags), int(algorithm), append(data, key...)}, true
}

// canonicalName returns a name in presentation format as lowercase wire format, as it's signed, and hashed for a DS
// record (RFC 4034 section 6.2). Only ASCII letters are lowered, since the other bytes of a label aren't letters at all.
func canonicalName(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}
	}
	wire := []byte{0}
	start := 0 //Where the current label's length goes.
	for i := 0; i < len(name); i++ {
		b := name[i]
		switch {
		case b == '\\' && i+1 < len(name):
			i++
			b = name[i]
		case b == '.':
			wire[start] = byte(len(wire) - start - 1)
			start = len(wire)
			wire = append(wire, 0)
			continue
		}
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		wire = append(wire, b)
	}
	wire[start] = byte(len(wire) - start - 1)
	return append(wire, 0)
}

// digestDS returns the digest a DS record should hold for key, or nil for a digest type this doesn't compute.
func digestDS(digestType int, zone string, key []byte) []byte {
	message := append(canonicalName(zone), key...)
	switch digestType {
	case digestSHA1:
		sum := sha1.Sum(message)
		return sum[:]
	case digestSHA256:
		sum := sha256.Sum256(message)
		return sum[:]
	case digestSHA384:
		sum := sha512.Sum384(message)
		return sum[:]
	}
	return nil
}

// checkDNSSEC tests how the zone is signed: the link from the DS records at the parent to the keys in the zone, which is
// what breaks when keys are changed carelessly, the chain above that, and the signatures in the zone.
func (c *dnsChecker) checkDNSSEC(ctx context.Context, servers []nameServer) error {
	dsValues, err := c.get(ctx, "dnssec-chain", rfcDNSSEC, c.zone, typeDS)
	keyValues, err2 := c.get(ctx, "dnssec-chain", rfcDNSSEC, c.zone, typeDNSKEY)
	if err != nil || err2 != nil {
		return errors.Join(err, err2)
	}
	if len(dsValues) > 0 && len(keyValues) == 0 {
		keyValues = c.askForKeys(ctx, servers)
	}
	switch {
	case len(dsValues) == 0 && len(keyValues) == 0:
		c.add("dnssec-status", SeverityInfo, rfcDNSSEC, "Not signed with DNSSEC, which doesn't affect the grade.")
		return nil
	case len(dsValues) == 0:
		c.add("dnssec-status", SeverityInfo, rfcDNSSEC, "Has DNSSEC keys, but no DS record at the parent, so nothing validates them.")
		return nil
	case len(keyValues) == 0:
		c.add("dnssec-chain", SeverityFailure, rfcDNSSEC, "The parent has a DS record, but the zone has no DNSKEY records, so validating resolvers will refuse the domain.")
		return nil
	}
	c.add("dnssec-status", SeverityInfo, rfcDNSSEC, "Signed with DNSSEC, which doesn't affect the grade.")

	algorithms := map[int]bool{}
	var keys []dnskeyRecord
	for _, value := range keyValues {
		if key, ok := parseDNSKEY(value); ok {
			keys = append(keys, key)
			algorithms[key.algorithm] = true
		}
	}
	strongDigest, verifiable := false, false
	var delegation []dsRecord
	for _, value := range dsValues {
		ds, ok := parseDS(value)
		if !ok {
			continue
		}
		delegation = append(delegation, ds)
		algorithms[ds.algorithm] = true
		strongDigest = strongDigest || ds.digestType == digestSHA256 || ds.digestType == digestSHA384
		verifiable = verifiable || digestDS(ds.digestType, c.zone, nil) != nil
	}
	matched := len(anchoredKeys(keys, delegation, c.zone)) > 0
	if verifiable && !matched {
		c.add("dnssec-chain", SeverityFailure, rfcDNSSEC, "No DS record at the parent matches a key in the zone, so validating resolvers will refuse the domain.")
	}
	if !strongDigest {
		c.add("dnssec-ds-digest", SeverityWarning, rfcDNSSECAlgs, "The DS records don't use SHA-256 or better.")
	}
	for _, number := range slices.Sorted(maps.Keys(algorithms)) {
		if name, deprecated := deprecatedDNSSECAlgorithms[number]; deprecated {
			c.add("dnssec-algorithm", SeverityWarning, rfcDNSSECAlgs, fmt.Sprintf("Signs with %s, which is deprecated.", name))
		}
	}
	err = c.checkChain(ctx)
	if matched {
		return errors.Join(err, c.checkSignatures(ctx, servers, delegation))
	}
	return err
}
