package robertparker

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

//DNS record collection. net.Resolver can't ask for most of these types, so this makes the queries itself.

const (
	// These types aren't named by dnsmessage, which hands them over as raw bytes.
	typeDS     dnsmessage.Type = 43
	typeRRSIG  dnsmessage.Type = 46
	typeDNSKEY dnsmessage.Type = 48
	typeCAA    dnsmessage.Type = 257

	recordTimeout  = 3 * time.Second
	recordAttempts = 2

	// directTimeout is how long a name server gets to answer for itself, which it does at once, unlike a resolver.
	directTimeout = 2 * time.Second

	// recordUDPSize is the UDP response size to ask for, which avoids fragmentation (DNS Flag Day 2020).
	recordUDPSize = 1232

	// maxNameJumps is how many compression pointers a name can follow, which stops names that point at each other.
	maxNameJumps = 16
)

// labelEscaper writes a label of a name in presentation format, where a dot in a label is escaped.
var labelEscaper = strings.NewReplacer(`\`, `\\`, `.`, `\.`)

// recordTypes are the types to collect. Each has its own query, because ANY is unreliable (RFC 8482).
var recordTypes = []struct {
	name string
	code dnsmessage.Type
}{
	{"A", dnsmessage.TypeA},
	{"AAAA", dnsmessage.TypeAAAA},
	{"CNAME", dnsmessage.TypeCNAME},
	{"NS", dnsmessage.TypeNS},
	{"SOA", dnsmessage.TypeSOA},
	{"MX", dnsmessage.TypeMX},
	{"TXT", dnsmessage.TypeTXT},
	{"CAA", typeCAA},
	{"DS", typeDS},
	{"DNSKEY", typeDNSKEY},
	{"HTTPS", dnsmessage.TypeHTTPS},
	{"SVCB", dnsmessage.TypeSVCB},
}

// RecordsAnalyzer returns an Analyzer that collects a domain's DNS records into d.Records, by type, each value in
// presentation format. It looks up the host as given. server is the DNS server to ask, as host or host:port, and if
// it's empty, the system's is used. Every query goes through limiter, which can be nil.
//
// A type that can't be looked up is counted in d.RecordFailures and returns an error, so that a missing type can be told
// apart from one that doesn't exist.
func RecordsAnalyzer(server string, limiter *Limiter) Analyzer {
	r := &recordLookup{server: server, limiter: limiter}
	return func(ctx context.Context, d *Domain) error {
		name := d.hostname()
		if d.registrable() == "" {
			name = d.Suffix
		}
		if name == "" {
			return nil
		}
		records := map[string][]string{}
		failures := 0
		var firstErr error
		for _, t := range recordTypes {
			values, err := r.lookup(ctx, name, t.code)
			if err != nil {
				failures++
				if firstErr == nil {
					firstErr = fmt.Errorf("%s: %w", t.name, err)
				}
				continue
			}
			if len(values) > 0 {
				records[t.name] = values
			}
		}
		d.Records, d.RecordFailures = nil, failures
		if len(records) > 0 {
			d.Records = records
		}
		if failures > 0 {
			return fmt.Errorf("%d of %d record lookups failed: %w", failures, len(recordTypes), firstErr)
		}
		return nil
	}
}

// recordLookup makes DNS queries.
type recordLookup struct {
	server  string
	limiter *Limiter
	rewrite func(address string) string //Changes where direct queries go, for tests.
	anchors []string                    //Replaces rootAnchors, for tests.

	mu      sync.Mutex
	address string //Where to send queries, once it's known.
}

// serverAddress returns where to send queries.
func (r *recordLookup) serverAddress(ctx context.Context) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.address != "" {
		return r.address, nil
	}
	address := r.server
	if address == "" {
		system, err := systemDNSServer(ctx)
		if err != nil {
			return "", err
		}
		address = system
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		address = net.JoinHostPort(address, "53")
	}
	r.address = address
	return address, nil
}

// systemDNSServer finds the system's DNS server. Go doesn't say what it is, but its resolver passes the address to Dial,
// so this starts a lookup that gets that far.
func systemDNSServer(ctx context.Context) (string, error) {
	var mu sync.Mutex
	var found string
	resolver := &net.Resolver{PreferGo: true, Dial: func(_ context.Context, _, address string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		found = address
		return nil, errors.New("only finding the server")
	}}
	resolver.LookupHost(ctx, randomName("example")) // The error is expected.
	mu.Lock()
	defer mu.Unlock()
	if found == "" {
		return "", errors.New("couldn't find the system's DNS server")
	}
	return found, nil
}

// lookup returns the records of one type at name, in presentation format and sorted, or nothing if there are none.
func (r *recordLookup) lookup(ctx context.Context, name string, code dnsmessage.Type) ([]string, error) {
	answers, err := r.answers(ctx, name, code)
	if err != nil {
		return nil, err
	}
	return presentAnswers(answers, code), nil
}

// presentAnswers returns the answers of one type, in presentation format and sorted.
func presentAnswers(answers []dnsmessage.Resource, code dnsmessage.Type) []string {
	var values []string
	for _, answer := range answers {
		if answer.Header.Type == code {
			values = append(values, presentRecord(answer.Body))
		}
	}
	slices.SortFunc(values, compareRecords)
	return values
}

// isAlias reports whether answers show that name is a CNAME. A resolver includes the CNAMEs it followed.
func isAlias(answers []dnsmessage.Resource, name string) bool {
	for _, answer := range answers {
		if answer.Header.Type == dnsmessage.TypeCNAME && strings.EqualFold(presentName(answer.Header.Name), name) {
			return true
		}
	}
	return false
}

// answers returns the answers to a query for one type at name, or nothing if name doesn't exist.
func (r *recordLookup) answers(ctx context.Context, name string, code dnsmessage.Type) ([]dnsmessage.Resource, error) {
	return r.resolve(ctx, name, code, false)
}

// signedAnswers is answers, with the RRSIG records that go with them.
func (r *recordLookup) signedAnswers(ctx context.Context, name string, code dnsmessage.Type) ([]dnsmessage.Resource, error) {
	return r.resolve(ctx, name, code, true)
}

func (r *recordLookup) resolve(ctx context.Context, name string, code dnsmessage.Type, signed bool) ([]dnsmessage.Resource, error) {
	reply, err := r.query(ctx, name, code, signed)
	if err != nil {
		return nil, err
	}
	switch reply.header.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return nil, nil
	default:
		return nil, fmt.Errorf("the server answered %s", reply.header.RCode.GoString())
	}
	return reply.answers, nil
}

// query asks the resolver about name, and returns the reply, whatever its response code. A name whose CNAME leads nowhere
// comes back with both the CNAME and a response code saying that the name doesn't exist.
func (r *recordLookup) query(ctx context.Context, name string, code dnsmessage.Type, signed bool) (dnsReply, error) {
	address, err := r.serverAddress(ctx)
	if err != nil {
		return dnsReply{}, err
	}
	return r.ask(ctx, "udp", address, name, code, true, signed, recordAttempts)
}

// dnsReply is what's read from a reply.
type dnsReply struct {
	header               dnsmessage.Header
	answers, authorities []dnsmessage.Resource
}

// ask sends a query to address, and returns the reply, whatever its response code. Over UDP, it makes up to attempts
// tries if there's a timeout, and if the answer doesn't fit, it goes over TCP. A recursive query asks the server to find
// the answer, and any other asks only what it knows itself. A signed query asks for RRSIG records as well.
func (r *recordLookup) ask(ctx context.Context, network, address, name string, code dnsmessage.Type, recursive, signed bool, attempts int) (dnsReply, error) {
	question, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return dnsReply{}, err
	}
	query, id, err := buildQuery(question, code, recursive, signed)
	if err != nil {
		return dnsReply{}, err
	}

	timeout := directTimeout
	if recursive {
		timeout = recordTimeout
	}
	var raw []byte
	for attempt := 1; ; attempt++ {
		err = r.limiter.Do(ctx, func(ctx context.Context) error {
			var err error
			raw, err = exchange(ctx, network, address, query, id, timeout)
			return err
		})
		var netErr net.Error
		if err == nil || attempt >= attempts || !errors.As(err, &netErr) || !netErr.Timeout() || ctx.Err() != nil {
			break
		}
	}
	if err != nil {
		return dnsReply{}, err
	}
	reply, err := parseReply(raw, id, question, code)
	if err != nil {
		return dnsReply{}, err
	}
	if reply.header.Truncated && network == "udp" {
		return r.ask(ctx, "tcp", address, name, code, recursive, signed, 1)
	}
	return reply, nil
}

// compareRecords sorts values, comparing a leading number as a number, so that MX preference 5 comes before 10.
func compareRecords(a, b string) int {
	first, _, _ := strings.Cut(a, " ")
	second, _, _ := strings.Cut(b, " ")
	x, xErr := strconv.Atoi(first)
	y, yErr := strconv.Atoi(second)
	if xErr == nil && yErr == nil && x != y {
		return x - y
	}
	return strings.Compare(a, b)
}

// buildQuery makes a query, and returns it with its ID.
func buildQuery(name dnsmessage.Name, code dnsmessage.Type, recursive, signed bool) ([]byte, uint16, error) {
	var random [2]byte
	rand.Read(random[:])
	id := binary.BigEndian.Uint16(random[:])
	// Checking disabled asks a validating resolver for the records even if DNSSEC fails, since its failure looks the same
	// as a server that's down, and a broken chain is something to report.
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: recursive, CheckingDisabled: recursive})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, 0, err
	}
	if err := builder.Question(dnsmessage.Question{Name: name, Type: code, Class: dnsmessage.ClassINET}); err != nil {
		return nil, 0, err
	}
	if err := builder.StartAdditionals(); err != nil {
		return nil, 0, err
	}
	var edns dnsmessage.ResourceHeader
	if err := edns.SetEDNS0(recordUDPSize, dnsmessage.RCodeSuccess, signed); err != nil {
		return nil, 0, err
	}
	if err := builder.OPTResource(edns, dnsmessage.OPTResource{}); err != nil {
		return nil, 0, err
	}
	query, err := builder.Finish()
	return query, id, err
}

// exchange sends a query, and returns the first reply with the right ID. Over TCP, messages have a length prefix.
func exchange(ctx context.Context, network, address string, query []byte, id uint16, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()

	if network == "tcp" {
		framed := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
		if _, err := conn.Write(append(framed, query...)); err != nil {
			return nil, err
		}
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return nil, err
		}
		reply := make([]byte, binary.BigEndian.Uint16(size[:]))
		_, err := io.ReadFull(conn, reply)
		return reply, err
	}

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			return nil, err
		}
		// A reply with the wrong ID could be a late one or a spoofed one, and either way isn't this answer.
		if n >= 2 && binary.BigEndian.Uint16(buffer) == id {
			return buffer[:n], nil
		}
	}
}

// parseReply checks that a reply answers the question, and returns its header and answers.
func parseReply(raw []byte, id uint16, name dnsmessage.Name, code dnsmessage.Type) (dnsReply, error) {
	var reply dnsReply
	var parser dnsmessage.Parser
	var err error
	if reply.header, err = parser.Start(raw); err != nil {
		return reply, fmt.Errorf("bad reply: %w", err)
	}
	if reply.header.ID != id || !reply.header.Response {
		return reply, errors.New("bad reply: not an answer to this query")
	}
	questions, err := parser.AllQuestions()
	if err != nil {
		return reply, fmt.Errorf("bad reply: %w", err)
	}
	if len(questions) != 1 || questions[0].Type != code || !strings.EqualFold(questions[0].Name.String(), name.String()) {
		return reply, errors.New("bad reply: it answers a different question")
	}
	if reply.header.Truncated {
		return reply, nil
	}
	if reply.answers, err = readSection(&parser, raw, parser.AnswerHeader, parser.Answer); err != nil {
		return reply, fmt.Errorf("bad reply: %w", err)
	}
	if reply.authorities, err = readSection(&parser, raw, parser.AuthorityHeader, parser.Authority); err != nil {
		return reply, fmt.Errorf("bad reply: %w", err)
	}
	return reply, nil
}

// readSection reads the records of one section of a reply. SOA records are read by hand, because dnsmessage refuses a
// name with a dot inside a label. That's legal, and normal in the mailbox of an SOA record, like first\.last.example.com,
// and an empty answer carries one, so it would otherwise fail every lookup that finds nothing.
func readSection(parser *dnsmessage.Parser, raw []byte, header func() (dnsmessage.ResourceHeader, error), resource func() (dnsmessage.Resource, error)) ([]dnsmessage.Resource, error) {
	var resources []dnsmessage.Resource
	for {
		h, err := header()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return resources, nil
		}
		if err != nil {
			return nil, err
		}
		if h.Type != dnsmessage.TypeSOA {
			r, err := resource()
			if err != nil {
				return nil, err
			}
			resources = append(resources, r)
			continue
		}
		unknown, err := parser.UnknownResource()
		if err != nil {
			return nil, err
		}
		soa, err := parseSOA(raw, unknown.Data)
		if err != nil {
			return nil, err
		}
		resources = append(resources, dnsmessage.Resource{Header: h, Body: soa})
	}
}

// parseSOA parses the data of an SOA record. Its names can point to anywhere in message.
func parseSOA(message, data []byte) (*dnsmessage.SOAResource, error) {
	server, data, err := readName(message, data)
	if err != nil {
		return nil, err
	}
	mailbox, data, err := readName(message, data)
	if err != nil {
		return nil, err
	}
	if len(data) < 20 {
		return nil, errors.New("SOA record is too short")
	}
	soa := &dnsmessage.SOAResource{
		Serial:  binary.BigEndian.Uint32(data),
		Refresh: binary.BigEndian.Uint32(data[4:]),
		Retry:   binary.BigEndian.Uint32(data[8:]),
		Expire:  binary.BigEndian.Uint32(data[12:]),
		MinTTL:  binary.BigEndian.Uint32(data[16:]),
	}
	if soa.NS, err = dnsmessage.NewName(server); err != nil {
		return nil, err
	}
	if soa.MBox, err = dnsmessage.NewName(mailbox); err != nil {
		return nil, err
	}
	return soa, nil
}

// readName reads the name at the start of data, in presentation format, and returns it with what follows it.
func readName(message, data []byte) (string, []byte, error) {
	var labels []string
	var rest []byte
	followed := false
	for jumps := 0; jumps <= maxNameJumps; {
		if len(data) == 0 {
			return "", nil, errors.New("name is cut off")
		}
		size := int(data[0])
		switch {
		case size == 0:
			if !followed {
				rest = data[1:]
			}
			return strings.Join(labels, ".") + ".", rest, nil
		case size&0xC0 == 0xC0:
			if len(data) < 2 {
				return "", nil, errors.New("name is cut off")
			}
			if !followed {
				rest, followed = data[2:], true
			}
			offset := int(binary.BigEndian.Uint16(data) & 0x3FFF)
			if offset >= len(message) {
				return "", nil, errors.New("name points outside the message")
			}
			data = message[offset:]
			jumps++
		case size&0xC0 != 0 || len(data) < 1+size:
			return "", nil, errors.New("name has a bad label")
		default:
			labels = append(labels, labelEscaper.Replace(string(data[1:1+size])))
			data = data[1+size:]
		}
	}
	return "", nil, errors.New("name points to itself")
}

// presentName returns a name in lowercase, without its final dot, unless it's the root, which is just a dot.
func presentName(name dnsmessage.Name) string {
	if name.String() == "." {
		return "."
	}
	return strings.ToLower(strings.TrimSuffix(name.String(), "."))
}

// presentRecord returns a record in presentation format, the same as it would be in a zone file.
func presentRecord(body dnsmessage.ResourceBody) string {
	switch r := body.(type) {
	case *dnsmessage.AResource:
		return netip.AddrFrom4(r.A).String()
	case *dnsmessage.AAAAResource:
		return netip.AddrFrom16(r.AAAA).String()
	case *dnsmessage.CNAMEResource:
		return presentName(r.CNAME)
	case *dnsmessage.NSResource:
		return presentName(r.NS)
	case *dnsmessage.MXResource:
		return fmt.Sprintf("%d %s", r.Pref, presentName(r.MX))
	case *dnsmessage.TXTResource:
		return strings.Join(r.TXT, "")
	case *dnsmessage.SOAResource:
		return fmt.Sprintf("%s %s %d %d %d %d %d", presentName(r.NS), presentName(r.MBox), r.Serial, r.Refresh, r.Retry, r.Expire, r.MinTTL)
	case *dnsmessage.HTTPSResource:
		return presentService(r.SVCBResource)
	case *dnsmessage.SVCBResource:
		return presentService(*r)
	case *dnsmessage.UnknownResource:
		return presentRaw(r)
	}
	return fmt.Sprint(body)
}

// presentService returns an HTTPS or SVCB record.
func presentService(r dnsmessage.SVCBResource) string {
	parts := []string{strconv.Itoa(int(r.Priority)), presentName(r.Target)}
	for _, p := range r.Params {
		parts = append(parts, presentServiceParam(p))
	}
	return strings.Join(parts, " ")
}

// presentServiceParam returns one parameter of an HTTPS or SVCB record.
func presentServiceParam(p dnsmessage.SVCParam) string {
	v := p.Value
	switch p.Key {
	case dnsmessage.SVCParamNoDefaultALPN:
		return "no-default-alpn" // dnsmessage's own names for these aren't the standard ones.
	case dnsmessage.SVCParamDOHPath:
		return "dohpath=" + string(v)
	case dnsmessage.SVCParamTLSSupportedGroups:
		return "tls-supported-groups=" + base64.StdEncoding.EncodeToString(v)
	case dnsmessage.SVCParamALPN:
		var protocols []string
		for len(v) > 0 && int(v[0]) < len(v) {
			protocols = append(protocols, string(v[1:1+v[0]]))
			v = v[1+v[0]:]
		}
		return "alpn=" + strings.Join(protocols, ",")
	case dnsmessage.SVCParamPort:
		if len(v) == 2 {
			return "port=" + strconv.Itoa(int(binary.BigEndian.Uint16(v)))
		}
	case dnsmessage.SVCParamIPv4Hint, dnsmessage.SVCParamIPv6Hint:
		size, key := 4, "ipv4hint"
		if p.Key == dnsmessage.SVCParamIPv6Hint {
			size, key = 16, "ipv6hint"
		}
		var addresses []string
		for ; len(v) >= size; v = v[size:] {
			if address, ok := netip.AddrFromSlice(v[:size]); ok {
				addresses = append(addresses, address.String())
			}
		}
		return key + "=" + strings.Join(addresses, ",")
	}
	if len(p.Value) == 0 {
		return strings.ToLower(p.Key.String())
	}
	return strings.ToLower(p.Key.String()) + "=" + base64.StdEncoding.EncodeToString(p.Value)
}

// presentRaw returns a record of a type dnsmessage doesn't parse. One too short to read is shown as hex (RFC 3597).
func presentRaw(r *dnsmessage.UnknownResource) string {
	d := r.Data
	switch r.Type {
	case typeCAA:
		if len(d) >= 2 && len(d) >= 2+int(d[1]) {
			return fmt.Sprintf("%d %s %q", d[0], d[2:2+int(d[1])], d[2+int(d[1]):])
		}
	case typeDS:
		if len(d) >= 4 {
			return fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(d), d[2], d[3], strings.ToUpper(hex.EncodeToString(d[4:])))
		}
	case typeDNSKEY:
		if len(d) >= 4 {
			return fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(d), d[2], d[3], base64.StdEncoding.EncodeToString(d[4:]))
		}
	}
	return fmt.Sprintf("\\# %d %s", len(d), hex.EncodeToString(d))
}
