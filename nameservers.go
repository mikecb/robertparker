package robertparker

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/publicsuffix"
)

//Direct name server checks. A resolver hides a broken name server for as long as another one works, so these ask each
//server itself, with the same non-recursive queries a resolver sends.
//
//A failed query only says something about a name server if queries can get out at all, and many networks block them,
//or have no IPv6. So the parent zone's servers, which are always up, show what works from here.

const (
	rfcDelegation = "RFC 1034"
	rfcDNSTCP     = "RFC 7766"

	// parentServers is how many of a parent zone's servers to use. One is enough, and the rest are spares.
	parentServers = 3
)

// sharedAddressSpace is 100.64.0.0/10, for carrier-grade NAT, which also isn't reachable from the internet (RFC 6598).
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// internalAddress reports whether an address can't be reached from the internet. Names are chosen by whoever owns the
// domain, so without this check, a list of domains could send queries to machines on the local network.
func internalAddress(address netip.Addr) bool {
	address = address.Unmap()
	return address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() ||
		address.IsUnspecified() || sharedAddressSpace.Contains(address)
}

// firstPublic returns the first address that can be reached from the internet, or "".
func firstPublic(addresses []string) string {
	for _, s := range addresses {
		if address, err := netip.ParseAddr(s); err == nil && !internalAddress(address) {
			return s
		}
	}
	return ""
}

// direct sends a non-recursive query straight to a name server.
func (r *recordLookup) direct(ctx context.Context, network, ip, name string, code dnsmessage.Type, attempts int) (dnsReply, error) {
	address := net.JoinHostPort(ip, "53")
	if r.rewrite != nil {
		address = r.rewrite(address)
	}
	return r.ask(ctx, network, address, name, code, false, false, attempts)
}

// directSigned is direct, with the RRSIG records that go with the answers.
func (r *recordLookup) directSigned(ctx context.Context, ip, name string, code dnsmessage.Type) (dnsReply, error) {
	address := net.JoinHostPort(ip, "53")
	if r.rewrite != nil {
		address = r.rewrite(address)
	}
	return r.ask(ctx, "udp", address, name, code, false, true, recordAttempts)
}

// nameServer is one of a zone's name servers.
type nameServer struct {
	host       string
	ipv4, ipv6 string //The first address of each kind that can be reached from the internet.
}

// parentZone is the zone above a domain, and what its servers show about the network this is running on.
type parentZone struct {
	servers []string //Addresses of some of its name servers.
	tcp     bool     //Queries over TCP work from here.
	ipv6    bool     //Queries over IPv6 work from here.
}

// parentZones finds parent zones, keeping them, since a list of domains is mostly under a few. Only a success is kept, so
// a brief failure can't affect every domain that follows.
type parentZones struct {
	lookup *recordLookup
	mu     sync.Mutex
	known  map[string]*parentZone //By the name above the domain.
}

// get returns the zone above domain. A parent with no servers that could be found has none listed.
func (p *parentZones) get(ctx context.Context, domain string) (*parentZone, error) {
	_, above, found := strings.Cut(domain, ".")
	if !found {
		return &parentZone{}, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if parent, ok := p.known[above]; ok {
		return parent, nil
	}
	parent, err := p.find(ctx, above)
	if err != nil {
		return nil, err
	}
	if p.known == nil {
		p.known = map[string]*parentZone{}
	}
	p.known[above] = parent
	return parent, nil
}

// find looks up the nearest zone at or above name, since not every level of a public suffix is a zone of its own.
func (p *parentZones) find(ctx context.Context, name string) (*parentZone, error) {
	var hosts []string
	for {
		var err error
		if hosts, err = p.lookup.lookup(ctx, name, dnsmessage.TypeNS); err != nil {
			return nil, err
		}
		if len(hosts) > 0 {
			break
		}
		var found bool
		if _, name, found = strings.Cut(name, "."); !found {
			return &parentZone{}, nil
		}
	}

	parent := &parentZone{}
	var ipv6 []string
	var firstErr error
	for _, host := range hosts[:min(len(hosts), parentServers)] {
		addresses, err := p.lookup.lookup(ctx, host, dnsmessage.TypeA)
		if address := firstPublic(addresses); address != "" {
			parent.servers = append(parent.servers, address)
		}
		firstErr = firstError(firstErr, err)
		addresses, err = p.lookup.lookup(ctx, host, dnsmessage.TypeAAAA)
		if address := firstPublic(addresses); address != "" {
			ipv6 = append(ipv6, address)
		}
		firstErr = firstError(firstErr, err)
	}
	if len(parent.servers) == 0 && firstErr != nil {
		return nil, firstErr
	}

	for _, address := range parent.servers {
		if _, err := p.lookup.direct(ctx, "tcp", address, name, dnsmessage.TypeSOA, 1); err == nil {
			parent.tcp = true
			break
		}
	}
	for _, address := range ipv6 {
		if _, err := p.lookup.direct(ctx, "udp", address, name, dnsmessage.TypeSOA, 1); err == nil {
			parent.ipv6 = true
			break
		}
	}
	return parent, nil
}

// firstError returns the first error that isn't nil.
func firstError(a, b error) error {
	if a != nil {
		return a
	}
	return b
}

// serverReport is what one name server said.
type serverReport struct {
	host        string
	untested    bool     //There was no way to reach it from here.
	reached     bool     //It replied.
	authority   bool     //It claims to be an authority for the zone, which a redirected query never would.
	problem     string   //Why it doesn't answer for the zone, if it doesn't.
	serial      string   //The serial of its SOA record.
	nameServers []string //The name servers it lists.
	tcpError    error
	ipv6Error   error
}

// askServer asks one name server about the zone.
func (c *dnsChecker) askServer(ctx context.Context, s nameServer, parent *parentZone) serverReport {
	report := serverReport{host: s.host}
	address := s.ipv4
	if address == "" {
		if !parent.ipv6 {
			report.untested = true
			return report
		}
		address = s.ipv6
	}
	reply, err := c.lookup.direct(ctx, "udp", address, c.zone, dnsmessage.TypeSOA, recordAttempts)
	if err != nil {
		return report
	}
	report.reached = true
	report.authority = reply.header.Authoritative && reply.header.RCode == dnsmessage.RCodeSuccess
	soa := presentAnswers(reply.answers, dnsmessage.TypeSOA)
	switch {
	case reply.header.RCode != dnsmessage.RCodeSuccess:
		report.problem = "answers " + strings.TrimPrefix(reply.header.RCode.String(), "RCode")
	case !reply.header.Authoritative || len(soa) == 0:
		report.problem = "doesn't answer for the zone"
	}
	if report.problem != "" {
		return report
	}
	if fields := strings.Fields(soa[0]); len(fields) == 7 {
		report.serial = fields[2]
	}
	if reply, err := c.lookup.direct(ctx, "udp", address, c.zone, dnsmessage.TypeNS, recordAttempts); err == nil && reply.header.Authoritative {
		report.nameServers = presentAnswers(reply.answers, dnsmessage.TypeNS)
	}
	if parent.tcp {
		_, report.tcpError = c.lookup.direct(ctx, "tcp", address, c.zone, dnsmessage.TypeSOA, recordAttempts)
	}
	if parent.ipv6 && s.ipv6 != "" && address != s.ipv6 {
		_, report.ipv6Error = c.lookup.direct(ctx, "udp", s.ipv6, c.zone, dnsmessage.TypeSOA, recordAttempts)
	}
	return report
}

// askForKeys asks the name servers for the zone's DNSKEY records. With checking disabled, a resolver can pass on an empty
// answer from one server, as happened with cdc.gov, and saying a domain is offline is too serious to rest on that.
func (c *dnsChecker) askForKeys(ctx context.Context, servers []nameServer) []string {
	for _, s := range servers {
		address := s.ipv4
		if address == "" {
			address = s.ipv6
		}
		reply, err := c.lookup.direct(ctx, "udp", address, c.zone, typeDNSKEY, 1)
		if err != nil {
			continue
		}
		if keys := presentAnswers(reply.answers, typeDNSKEY); len(keys) > 0 {
			return keys
		}
	}
	return nil
}

// checkDirect asks each name server about the zone, and compares what they say.
//
// The zone resolved, so at least one of its servers works. If none could be asked, the problem is on this side, so
// nothing is known. Otherwise, a server that replies with something wrong is broken, but one that doesn't reply is only
// a warning, since it could be something on the way there that dropped the query.
func (c *dnsChecker) checkDirect(ctx context.Context, servers []nameServer) error {
	if len(servers) == 0 {
		return nil
	}
	parent, err := c.parents.get(ctx, c.zone)
	if err != nil {
		c.add("dns-ns-parent", SeverityUnknown, rfcDelegation, fmt.Sprintf("Couldn't find the zone above %s: %v", c.zone, err))
		return fmt.Errorf("DNS lookup: %w", err)
	}

	reports := make([]serverReport, len(servers))
	var wait sync.WaitGroup
	for i, server := range servers {
		wait.Go(func() { reports[i] = c.askServer(ctx, server, parent) })
	}
	wait.Wait()

	// Out of time, a server that didn't get to answer says nothing about the server. The clock is checked as well as ctx,
	// because a query's deadline is the same moment, and can arrive first.
	deadline, limited := ctx.Deadline()
	if ctx.Err() != nil || limited && !time.Now().Before(deadline) {
		c.add("dns-ns-lame", SeverityUnknown, rfcDelegation, "Ran out of time asking the name servers.")
		return fmt.Errorf("ran out of time asking the name servers of %s", c.zone)
	}
	if !slices.ContainsFunc(reports, func(r serverReport) bool { return r.authority }) {
		c.add("dns-ns-lame", SeverityUnknown, rfcDelegation, "Couldn't ask the name servers directly, which usually means that the network running this blocks or redirects DNS queries.")
		return fmt.Errorf("no answer from the name servers of %s", c.zone)
	}

	for i := range reports {
		r := &reports[i]
		switch {
		case r.untested:
		case !r.reached:
			c.add("dns-ns-respond", SeverityWarning, rfcDelegation, fmt.Sprintf("Name server %s didn't reply.", r.host))
		case r.problem != "":
			c.add("dns-ns-lame", SeverityFailure, rfcDelegation, fmt.Sprintf("Name server %s %s, so this is a lame delegation.", r.host, r.problem))
		}
		if r.tcpError != nil {
			c.add("dns-ns-tcp", SeverityWarning, rfcDNSTCP, fmt.Sprintf("Name server %s doesn't answer over TCP: %v", r.host, r.tcpError))
		}
		if r.ipv6Error != nil {
			c.add("dns-ns-ipv6-answer", SeverityWarning, "", fmt.Sprintf("Name server %s has an IPv6 address, but doesn't answer on it: %v", r.host, r.ipv6Error))
		}
	}
	c.checkSerials(reports)
	var untested []string
	if !parent.tcp {
		untested = append(untested, "TCP")
	}
	if !parent.ipv6 {
		untested = append(untested, "IPv6")
	}
	if len(untested) > 0 {
		c.add("dns-ns-untested", SeverityInfo, "", fmt.Sprintf("Queries over %s don't work from here, so the name servers weren't tested over it.", strings.Join(untested, " or ")))
	}
	return c.checkParent(ctx, parent, reports)
}

// checkSerials checks that every name server has the same version of the zone. Only servers under one domain have to
// match. A zone run by two DNS providers, which is a strong setup, is numbered separately by each, so across domains a
// difference is only information.
func (c *dnsChecker) checkSerials(reports []serverReport) {
	serials := map[string]bool{}
	byOperator := map[string]map[string]bool{}
	var details []string
	for _, r := range reports {
		if r.serial == "" {
			continue
		}
		operator, err := publicsuffix.EffectiveTLDPlusOne(r.host)
		if err != nil {
			operator = r.host
		}
		if byOperator[operator] == nil {
			byOperator[operator] = map[string]bool{}
		}
		byOperator[operator][r.serial] = true
		serials[r.serial] = true
		details = append(details, r.host+" has "+r.serial)
	}
	for _, seen := range byOperator {
		if len(seen) > 1 {
			c.add("dns-ns-serial", SeverityWarning, rfcDelegation, fmt.Sprintf("The name servers have different SOA serials: %s.", strings.Join(details, ", ")))
			return
		}
	}
	if len(serials) > 1 {
		c.add("dns-ns-serial", SeverityInfo, rfcDelegation, "The name servers under different domains have different SOA serials, which is normal with more than one DNS provider.")
	}
}

// checkParent checks that the parent zone and the name servers list the same name servers. The parent's list is in the
// authority section of a referral, or in the answer if the same servers run both zones. Having nothing to say about the
// zone isn't a problem, since the delegation may be somewhere else.
func (c *dnsChecker) checkParent(ctx context.Context, parent *parentZone, reports []serverReport) error {
	var listed []string
	asked := false
	for _, address := range parent.servers {
		reply, err := c.lookup.direct(ctx, "udp", address, c.zone, dnsmessage.TypeNS, recordAttempts)
		if err != nil {
			continue
		}
		asked = true
		listed = presentAnswers(reply.answers, dnsmessage.TypeNS)
		if len(listed) == 0 {
			delegation := slices.DeleteFunc(reply.authorities, func(r dnsmessage.Resource) bool {
				return !strings.EqualFold(presentName(r.Header.Name), c.zone)
			})
			listed = presentAnswers(delegation, dnsmessage.TypeNS)
		}
		break
	}
	if !asked {
		if len(parent.servers) == 0 {
			return nil
		}
		c.add("dns-ns-parent", SeverityUnknown, rfcDelegation, fmt.Sprintf("Couldn't ask the zone above %s for its name servers.", c.zone))
		return fmt.Errorf("no answer from the zone above %s", c.zone)
	}
	// Everything the servers list between them, since each of two DNS providers may list only its own.
	var inZone []string
	for _, r := range reports {
		inZone = append(inZone, r.nameServers...)
	}
	slices.Sort(inZone)
	inZone = slices.Compact(inZone)
	if len(listed) == 0 || len(inZone) == 0 {
		return nil
	}
	onlyParent := slices.DeleteFunc(slices.Clone(listed), func(host string) bool { return slices.Contains(inZone, host) })
	onlyZone := slices.DeleteFunc(inZone, func(host string) bool { return slices.Contains(listed, host) })
	if len(onlyParent) > 0 {
		c.add("dns-ns-parent", SeverityWarning, rfcDelegation, fmt.Sprintf("The parent zone lists name servers the zone doesn't: %s.", strings.Join(onlyParent, ", ")))
	}
	if len(onlyZone) > 0 {
		c.add("dns-ns-parent", SeverityWarning, rfcDelegation, fmt.Sprintf("The zone lists name servers the parent doesn't: %s.", strings.Join(onlyZone, ", ")))
	}
	return nil
}
