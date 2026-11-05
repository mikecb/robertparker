package robertparker

import "context"

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

// ReadName exports readName to the tests.
var ReadName = readName

// DNSAnalyzerRouted is a DNSAnalyzer that sends what's meant for a name server to the address rewrite returns.
func DNSAnalyzerRouted(server string, limiter *Limiter, rewrite func(address string) string) Analyzer {
	return newDNSAnalyzer(&recordLookup{server: server, limiter: limiter, rewrite: rewrite})
}
