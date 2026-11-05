package robertparker_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mikecb/robertparker"
	"golang.org/x/net/dns/dnsmessage"
)

// dnsServer is a real DNS server on localhost, over UDP and TCP, on one port.
type dnsServer struct {
	addr    string
	answers map[string][]dnsmessage.ResourceBody //By "name type", where name has its final dot.
	rcode   dnsmessage.RCode                     //Sent for anything not in answers.

	truncate   bool //Over UDP, say the answer didn't fit.
	silent     int  //Ignore this many queries.
	spoof      bool //Over UDP, send a reply with the wrong ID first.
	wrongQuery bool //Answer a different question.

	authorities      map[string][]dnsmessage.ResourceBody //In the authority section, by "name type".
	notAuthoritative bool                                 //Don't claim to be an authority.
	noTCP            bool                                 //Close TCP connections at once.

	mu               sync.Mutex
	queries          []string
	checkingDisabled bool //A query asked for records even if DNSSEC validation fails.
	recursive        bool //A query asked the server to find the answer.
	tcp              atomic.Int64
}

// listenBoth listens on the same TCP and UDP port. It chooses the port itself, from
// below the range the system hands out. Port 0 only finds a port that's free for
// one protocol, and Windows reserves blocks of 100 ports in that range, so trying
// the next one can fail many times in a row.
func listenBoth(t *testing.T) (net.Listener, net.PacketConn) {
	t.Helper()
	var last error
	for range 50 {
		port := 20000 + rand.IntN(12000)
		packets, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			last = err
			continue
		}
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			return listener, packets
		}
		packets.Close()
		last = err
	}
	t.Fatal(last)
	return nil, nil
}

func startDNS(t *testing.T, s *dnsServer) string {
	t.Helper()
	listener, packets := listenBoth(t)
	t.Cleanup(func() { listener.Close(); packets.Close() })
	s.addr = listener.Addr().String()

	go func() {
		buffer := make([]byte, 4096)
		for {
			n, from, err := packets.ReadFrom(buffer)
			if err != nil {
				return
			}
			reply, id := s.answer(buffer[:n], true)
			if reply == nil {
				continue
			}
			if s.spoof {
				bad := append([]byte{}, reply...)
				binary.BigEndian.PutUint16(bad, id+1)
				packets.WriteTo(bad, from)
			}
			packets.WriteTo(reply, from)
		}
	}()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if s.noTCP {
					return
				}
				var size [2]byte
				if _, err := io.ReadFull(conn, size[:]); err != nil {
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				s.tcp.Add(1)
				reply, _ := s.answer(query, false)
				conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(reply))), reply...))
			}()
		}
	}()
	return s.addr
}

// asked returns the queries so far.
func (s *dnsServer) asked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.queries)
}

func (s *dnsServer) answer(query []byte, udp bool) ([]byte, uint16) {
	var message dnsmessage.Message
	if err := message.Unpack(query); err != nil || len(message.Questions) != 1 {
		return nil, 0
	}
	question := message.Questions[0]
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = append(s.queries, question.Name.String()+" "+question.Type.String())
	s.checkingDisabled = s.checkingDisabled || message.CheckingDisabled
	s.recursive = s.recursive || message.RecursionDesired
	if s.silent > 0 {
		s.silent--
		return nil, 0
	}
	reply := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: message.ID, Response: true, RCode: s.rcode,
			Authoritative: !message.RecursionDesired && !s.notAuthoritative,
		},
		Questions: message.Questions,
	}
	for _, body := range s.authorities[question.Name.String()+" "+question.Type.String()] {
		reply.Authorities = append(reply.Authorities, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   body,
		})
	}
	if s.wrongQuery {
		reply.Questions = []dnsmessage.Question{{Name: dnsmessage.MustNewName("other.example."), Type: question.Type, Class: question.Class}}
	}
	if udp && s.truncate {
		reply.Truncated = true
	} else if bodies, ok := s.answers[question.Name.String()+" "+question.Type.String()]; ok {
		reply.RCode = dnsmessage.RCodeSuccess
		for _, body := range bodies {
			reply.Answers = append(reply.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   body,
			})
		}
	}
	packed, err := reply.Pack()
	if err != nil {
		panic(err)
	}
	return packed, message.ID
}

func name(s string) dnsmessage.Name { return dnsmessage.MustNewName(s) }

// exampleZone has a record of every type.
func exampleZone() map[string][]dnsmessage.ResourceBody {
	const (
		typeA      = "TypeA"
		typeAAAA   = "TypeAAAA"
		typeCNAME  = "TypeCNAME"
		typeNS     = "TypeNS"
		typeSOA    = "TypeSOA"
		typeMX     = "TypeMX"
		typeTXT    = "TypeTXT"
		typeHTTPS  = "TypeHTTPS"
		typeSVCB   = "TypeSVCB"
		typeCAA    = "257"
		typeDS     = "43"
		typeDNSKEY = "48"
	)
	key := func(t string) string { return "example.com. " + t }
	var ipv6 [16]byte
	ipv6[0], ipv6[1], ipv6[15] = 0x20, 0x01, 1
	return map[string][]dnsmessage.ResourceBody{
		key(typeA):     {&dnsmessage.AResource{A: [4]byte{192, 0, 2, 2}}, &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}},
		key(typeAAAA):  {&dnsmessage.AAAAResource{AAAA: ipv6}},
		key(typeCNAME): {&dnsmessage.CNAMEResource{CNAME: name("Target.Example.net.")}},
		key(typeNS):    {&dnsmessage.NSResource{NS: name("ns2.example.net.")}, &dnsmessage.NSResource{NS: name("ns1.example.net.")}},
		key(typeSOA): {&dnsmessage.SOAResource{
			NS: name("ns1.example.net."), MBox: name("admin.example.net."),
			Serial: 2026110501, Refresh: 7200, Retry: 3600, Expire: 1209600, MinTTL: 300,
		}},
		key(typeMX):  {&dnsmessage.MXResource{Pref: 10, MX: name("mail.example.com.")}},
		key(typeTXT): {&dnsmessage.TXTResource{TXT: []string{"v=spf1 ", "-all"}}},
		key(typeHTTPS): {&dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{
			Priority: 1, Target: name("."),
			Params: []dnsmessage.SVCParam{
				{Key: dnsmessage.SVCParamALPN, Value: []byte("\x02h3\x02h2")},
				{Key: dnsmessage.SVCParamNoDefaultALPN},
				{Key: dnsmessage.SVCParamPort, Value: []byte{0x01, 0xbb}},
				{Key: dnsmessage.SVCParamIPv4Hint, Value: []byte{192, 0, 2, 1, 192, 0, 2, 2}},
				{Key: dnsmessage.SVCParamIPv6Hint, Value: ipv6[:]},
			},
		}}},
		key(typeSVCB):   {&dnsmessage.SVCBResource{Priority: 0, Target: name("svc.example.net.")}},
		key(typeCAA):    {&dnsmessage.UnknownResource{Type: 257, Data: []byte("\x00\x05issueletsencrypt.org")}},
		key(typeDS):     {&dnsmessage.UnknownResource{Type: 43, Data: []byte{0x12, 0x34, 13, 2, 0xab, 0xcd}}},
		key(typeDNSKEY): {&dnsmessage.UnknownResource{Type: 48, Data: []byte{0x01, 0x01, 3, 13, 'k', 'e', 'y'}}},
	}
}

func collect1(t *testing.T, s *dnsServer, domain string) (*robertparker.Domain, error) {
	t.Helper()
	address := startDNS(t, s)
	d := robertparker.NewDomain(domain)
	err := robertparker.RecordsAnalyzer(address, nil)(context.Background(), d)
	return d, err
}

func TestRecordsEveryType(t *testing.T) {
	d, err := collect1(t, &dnsServer{answers: exampleZone()}, "www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"A":      {"192.0.2.1", "192.0.2.2"},
		"AAAA":   {"2001::1"},
		"CNAME":  {"target.example.net"},
		"NS":     {"ns1.example.net", "ns2.example.net"},
		"SOA":    {"ns1.example.net admin.example.net 2026110501 7200 3600 1209600 300"},
		"MX":     {"10 mail.example.com"},
		"TXT":    {"v=spf1 -all"},
		"CAA":    {`0 issue "letsencrypt.org"`},
		"DS":     {"4660 13 2 ABCD"},
		"DNSKEY": {"257 3 13 a2V5"},
		"HTTPS":  {"1 . alpn=h3,h2 no-default-alpn port=443 ipv4hint=192.0.2.1,192.0.2.2 ipv6hint=2001::1"},
		"SVCB":   {"0 svc.example.net"},
	}
	for kind, values := range want {
		if !reflect.DeepEqual(d.Records[kind], values) {
			t.Errorf("%s: got %q, want %q", kind, d.Records[kind], values)
		}
	}
	if len(d.Records) != len(want) || d.RecordFailures != 0 {
		t.Errorf("got %d types and %d failures: %v", len(d.Records), d.RecordFailures, d.Records)
	}
}

func TestRecordsNoneFound(t *testing.T) {
	for name, rcode := range map[string]dnsmessage.RCode{"NXDOMAIN": dnsmessage.RCodeNameError, "NODATA": dnsmessage.RCodeSuccess} {
		t.Run(name, func(t *testing.T) {
			d, err := collect1(t, &dnsServer{rcode: rcode}, "example.com")
			if err != nil || d.Records != nil || d.RecordFailures != 0 {
				t.Errorf("got %v, %v, %d failures", err, d.Records, d.RecordFailures)
			}
		})
	}
}

func TestRecordsServerFailure(t *testing.T) {
	d, err := collect1(t, &dnsServer{rcode: dnsmessage.RCodeServerFailure}, "example.com")
	if err == nil || !strings.Contains(err.Error(), "12 of 12") || d.RecordFailures != 12 {
		t.Errorf("got %v, %d failures", err, d.RecordFailures)
	}
}

func TestRecordsPartialFailure(t *testing.T) {
	zone := exampleZone()
	s := &dnsServer{answers: zone, rcode: dnsmessage.RCodeRefused}
	d, err := collect1(t, s, "example.com")
	if err != nil {
		t.Fatalf("every type has an answer, got %v", err)
	}
	if len(d.Records) != 12 {
		t.Errorf("got %d types", len(d.Records))
	}
	// A new zone, because the first server is still running, and it reads the old one.
	zone = exampleZone()
	delete(zone, "example.com. 257")
	d, err = collect1(t, &dnsServer{answers: zone, rcode: dnsmessage.RCodeRefused}, "example.com")
	if err == nil || d.RecordFailures != 1 || len(d.Records) != 11 {
		t.Errorf("got %v, %d failures, %d types", err, d.RecordFailures, len(d.Records))
	}
}

func TestRecordsFallBackToTCP(t *testing.T) {
	s := &dnsServer{answers: exampleZone(), truncate: true}
	d, err := collect1(t, s, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if s.tcp.Load() != 12 || len(d.Records) != 12 {
		t.Errorf("got %d TCP queries and %d types", s.tcp.Load(), len(d.Records))
	}
}

func TestRecordsRetryAfterATimeout(t *testing.T) {
	s := &dnsServer{answers: exampleZone(), silent: 1}
	d, err := collect1(t, s, "example.com")
	if err != nil || len(d.Records) != 12 {
		t.Errorf("got %v, %d types", err, len(d.Records))
	}
}

func TestRecordsIgnoreSpoofedReplies(t *testing.T) {
	s := &dnsServer{answers: exampleZone(), spoof: true}
	d, err := collect1(t, s, "example.com")
	if err != nil || len(d.Records) != 12 {
		t.Errorf("got %v, %d types", err, len(d.Records))
	}
}

func TestRecordsRejectAnswersToOtherQuestions(t *testing.T) {
	d, err := collect1(t, &dnsServer{answers: exampleZone(), wrongQuery: true}, "example.com")
	if err == nil || d.Records != nil || d.RecordFailures != 12 {
		t.Errorf("got %v, %v", err, d.Records)
	}
}

func TestRecordsQueryOneTypeAtATime(t *testing.T) {
	s := &dnsServer{}
	collect1(t, s, "example.com")
	queries := s.asked()
	seen := map[string]bool{}
	for _, q := range queries {
		seen[q] = true
		if strings.HasSuffix(q, "TypeALL") {
			t.Error("ANY isn't reliable, and shouldn't be used")
		}
	}
	if len(seen) != 12 {
		t.Errorf("got %d distinct queries: %v", len(seen), queries)
	}
}

func TestRecordsUseTheHostGivenInPunycode(t *testing.T) {
	s := &dnsServer{}
	collect1(t, s, "api.δοκιμή.com")
	queries := s.asked()
	if len(queries) == 0 || !strings.HasPrefix(queries[0], "api.xn--jxalpdlp.com. ") {
		t.Errorf("queried %v", queries)
	}
}

func TestRecordsOfABareSuffix(t *testing.T) {
	s := &dnsServer{}
	collect1(t, s, "com")
	queries := s.asked()
	if len(queries) == 0 || !strings.HasPrefix(queries[0], "com. ") {
		t.Errorf("queried %v", queries)
	}
}

// A dot inside a label is legal, and normal in the mailbox of an SOA record, but dnsmessage refuses it. An empty answer
// carries the SOA record, so it would fail every type that a domain doesn't have.
func TestRecordsDotInSOAMailbox(t *testing.T) {
	soa := append([]byte("\x03ns1\xc0\x0c"), "\x0afirst.last\xc0\x0c"...)
	soa = append(soa, make([]byte, 20)...)
	soa[len(soa)-1] = 60
	body := &dnsmessage.UnknownResource{Type: dnsmessage.TypeSOA, Data: soa}
	s := &dnsServer{
		answers:     map[string][]dnsmessage.ResourceBody{"example.com. TypeSOA": {body}},
		authorities: map[string][]dnsmessage.ResourceBody{"example.com. TypeTXT": {body}},
	}
	d, err := collect1(t, s, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := `ns1.example.com first\.last.example.com 0 0 0 0 60`
	if got := d.Records["SOA"]; len(got) != 1 || got[0] != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestReadName(t *testing.T) {
	message := []byte("\x07example\x03com\x00")
	tests := []struct {
		name, data, want, rest string
		bad                    bool
	}{
		{name: "plain", data: "\x01a\x03com\x00rest", want: "a.com.", rest: "rest"},
		{name: "root", data: "\x00rest", want: ".", rest: "rest"},
		{name: "pointer", data: "\x01a\xc0\x00rest", want: "a.example.com.", rest: "rest"},
		{name: "dot in a label", data: "\x03a.b\x00", want: `a\.b.`},
		{name: "backslash in a label", data: "\x03a\\b\x00", want: `a\\b.`},
		{name: "cut off", data: "\x03ab", bad: true},
		{name: "no end", data: "\x01a", bad: true},
		{name: "half a pointer", data: "\xc0", bad: true},
		{name: "pointer outside", data: "\xc0\xff", bad: true},
		{name: "reserved label type", data: "\x80a\x00", bad: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, rest, err := robertparker.ReadName(message, []byte(tt.data))
			if (err != nil) != tt.bad {
				t.Fatalf("got error %v", err)
			}
			if got != tt.want || string(rest) != tt.rest {
				t.Errorf("got %q, %q, want %q, %q", got, rest, tt.want, tt.rest)
			}
		})
	}
	t.Run("pointers in a loop", func(t *testing.T) {
		if _, _, err := robertparker.ReadName([]byte("\xc0\x00"), []byte("\xc0\x00")); err == nil {
			t.Error("no error")
		}
	})
}

func TestRecordsUnreachableServer(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.LocalAddr().String()
	listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	d := robertparker.NewDomain("example.com")
	if err := robertparker.RecordsAnalyzer(address, nil)(ctx, d); err == nil || d.RecordFailures == 0 {
		t.Errorf("got %v, %d failures", err, d.RecordFailures)
	}
}

func TestRecordsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &dnsServer{}
	address := startDNS(t, s)
	d := robertparker.NewDomain("example.com")
	start := time.Now()
	if err := robertparker.RecordsAnalyzer(address, nil)(ctx, d); err == nil || time.Since(start) > time.Second {
		t.Errorf("got %v after %v", err, time.Since(start))
	}
}

func TestSystemDNSServer(t *testing.T) {
	address, err := robertparker.SystemDNSServer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		t.Errorf("got %q: %v", address, err)
	}
}

func TestRecordsThroughProcess(t *testing.T) {
	s := &dnsServer{answers: exampleZone()}
	address := startDNS(t, s)
	ctx := context.Background()
	opts := robertparker.Options{Workers: 4, Analyzers: []robertparker.Analyzer{robertparker.RecordsAnalyzer(address, robertparker.NewLimiter(8, 0))}}
	for _, r := range collect(robertparker.Process(ctx, feed(ctx, []string{"example.com", "example.com"}), opts)) {
		if r.Err != nil || len(r.Domain.Records) != 12 {
			t.Errorf("got %v, %d types", r.Err, len(r.Domain.Records))
		}
	}
}

func TestRecordsSortByPreference(t *testing.T) {
	zone := map[string][]dnsmessage.ResourceBody{
		"example.com. TypeMX": {
			&dnsmessage.MXResource{Pref: 10, MX: name("b.example.com.")},
			&dnsmessage.MXResource{Pref: 5, MX: name("c.example.com.")},
			&dnsmessage.MXResource{Pref: 10, MX: name("a.example.com.")},
		},
	}
	d, err := collect1(t, &dnsServer{answers: zone}, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"5 c.example.com", "10 a.example.com", "10 b.example.com"}
	if !reflect.DeepEqual(d.Records["MX"], want) {
		t.Errorf("got %q, want %q", d.Records["MX"], want)
	}
}
