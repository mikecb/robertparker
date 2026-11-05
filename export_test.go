package robertparker

// PlainRegistrable exports plainRegistrable to the tests.
var PlainRegistrable = plainRegistrable

// SystemDNSServer exports systemDNSServer to the tests.
var SystemDNSServer = systemDNSServer

// ReadName exports readName to the tests.
var ReadName = readName

// DNSAnalyzerRouted is a DNSAnalyzer that sends what's meant for a name server to the address rewrite returns.
func DNSAnalyzerRouted(server string, limiter *Limiter, rewrite func(address string) string) Analyzer {
	return newDNSAnalyzer(&recordLookup{server: server, limiter: limiter, rewrite: rewrite})
}
