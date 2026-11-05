package robertparker

import (
	"context"
	"time"
)

// PlainRegistrable exports plainRegistrable to the tests.
var PlainRegistrable = plainRegistrable

// SystemDNSServer exports systemDNSServer to the tests.
var SystemDNSServer = systemDNSServer

// ProbeTLS runs the prober on its own.
func ProbeTLS(ctx context.Context, config WebConfig, d *Domain, host string) error {
	if config.ProbeTimeout == 0 {
		config.ProbeTimeout = probeTimeout
	}
	w := webChecker{config: config, domain: d}
	return w.probeTLS(ctx, host)
}

// TilePath exports tilePath to the tests.
var TilePath = tilePath

// ReadName exports readName to the tests.
var ReadName = readName

// DNSAnalyzerRouted is a DNSAnalyzer that sends what's meant for a name server to the address rewrite returns.
func DNSAnalyzerRouted(server string, limiter *Limiter, rewrite func(address string) string) Analyzer {
	return newDNSAnalyzer(&recordLookup{server: server, limiter: limiter, rewrite: rewrite})
}

// DNSAnalyzerAnchored is a DNSAnalyzerRouted that starts validating from anchors rather than the real root.
func DNSAnalyzerAnchored(server string, rewrite func(address string) string, anchors []string) Analyzer {
	return newDNSAnalyzer(&recordLookup{server: server, rewrite: rewrite, anchors: anchors})
}

// CanonicalName exports canonicalName to the tests.
var CanonicalName = canonicalName

// ValidKeySet reports whether an RRSIG record, given as its data, validates a zone's keys at a time.
func ValidKeySet(zone string, keys [][]byte, rrsig []byte, at time.Time) bool {
	sig, ok := parseRRSIG(rrsig)
	if !ok {
		return false
	}
	set := rrset{owner: zone, code: typeDNSKEY, records: keys, signatures: []signature{sig}}
	return set.validate(set.keys(), zone, at).state == signatureValid
}
