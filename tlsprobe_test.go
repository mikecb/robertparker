package robertparker_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mikecb/robertparker"
)

// probeSite runs a real TLS server, and probes it.
func probeSite(t *testing.T, config *tls.Config) *robertparker.Domain {
	t.Helper()
	site := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	site.TLS = config
	site.Config.ErrorLog = nil
	site.StartTLS()
	t.Cleanup(site.Close)
	d := robertparker.NewDomain("example.com")
	analyzer := robertparker.WebAnalyzer(robertparker.WebConfig{
		TLS: true, Probe: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, site.Listener.Addr().String())
		},
	}, nil)
	if err := analyzer(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	return d
}

// probeFindings returns the findings of the prober, by check.
func probeFindings(d *robertparker.Domain) map[string]robertparker.Finding {
	found := map[string]robertparker.Finding{}
	for _, f := range d.Findings {
		if slices.Contains([]string{
			"tls-legacy", "tls-cipher-broken", "tls-cipher-cbc",
			"tls-compression", "tls-renegotiation", "tls-probe",
		}, f.Check) {
			found[f.Check] = f
		}
	}
	return found
}

// Go's own TLS server parsing these is what shows that the hand-built ClientHello is right.
func TestProbeRealServers(t *testing.T) {
	modern := []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	tests := []struct {
		name    string
		config  *tls.Config
		check   string
		message string
	}{
		{"nothing wrong", &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: modern}, "", ""},
		{"TLS 1.3 only", &tls.Config{MinVersion: tls.VersionTLS13}, "", ""},
		{"TLS 1.0", &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}}, "tls-legacy", "Accepts TLS 1.0, which is deprecated."},
		{"TLS 1.1", &tls.Config{MinVersion: tls.VersionTLS11, CipherSuites: slices.Concat(modern, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA})}, "tls-legacy", "Accepts TLS 1.1, which is deprecated."},
		{"TLS 1.0 and 1.1", &tls.Config{MinVersion: tls.VersionTLS10, CipherSuites: slices.Concat(modern, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA})}, "tls-legacy", "Accepts TLS 1.0 and TLS 1.1, which are deprecated."},
		{"RC4", &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: slices.Concat(modern, []uint16{tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA})}, "tls-cipher-broken", "RC4"},
		{"3DES", &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: slices.Concat(modern, []uint16{tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA})}, "tls-legacy", "3DES"},
		{"RSA key exchange", &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: slices.Concat(modern, []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256})}, "tls-legacy", "RSA key exchange"},
		{"CBC", &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: slices.Concat(modern, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA})}, "tls-cipher-cbc", "CBC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := probeFindings(probeSite(t, tt.config))
			if tt.check == "" {
				if len(found) != 0 {
					t.Errorf("found %+v", found)
				}
				return
			}
			if !strings.Contains(found[tt.check].Message, tt.message) {
				t.Errorf("got %+v, want %q", found, tt.message)
			}
		})
	}
}

func TestProbeSendsTheHostName(t *testing.T) {
	var mu sync.Mutex
	names := map[string]bool{}
	probeSite(t, &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		mu.Lock()
		defer mu.Unlock()
		names[hello.ServerName] = true
		return nil, nil
	}})
	mu.Lock()
	defer mu.Unlock()
	if len(names) != 1 || !names["example.com"] {
		t.Errorf("got %v", names)
	}
}

// clientHello is what the fake server reads from a ClientHello.
type clientHello struct {
	version     uint16
	suites      []uint16
	compression []byte
}

func (h clientHello) offers(suite uint16) bool { return slices.Contains(h.suites, suite) }

func readClientHello(conn net.Conn) (clientHello, bool) {
	var header [5]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return clientHello{}, false
	}
	body := make([]byte, binary.BigEndian.Uint16(header[3:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		return clientHello{}, false
	}
	var hello clientHello
	hello.version = binary.BigEndian.Uint16(body[4:])
	rest := body[39:] // Past the type, length, version, random, and an empty session ID.
	size := int(binary.BigEndian.Uint16(rest))
	for i := 0; i < size; i += 2 {
		hello.suites = append(hello.suites, binary.BigEndian.Uint16(rest[2+i:]))
	}
	rest = rest[2+size:]
	hello.compression = rest[1 : 1+int(rest[0])]
	return hello, true
}

var alert = []byte{21, 3, 3, 0, 2, 2, 40}

// serverHelloRecord returns a ServerHello in one record.
func serverHelloRecord(version, suite uint16, compression byte, renegotiation bool) []byte {
	body := binary.BigEndian.AppendUint16(nil, version)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, suite)
	body = append(body, compression)
	if renegotiation {
		body = append(body, 0, 5, 0xff, 0x01, 0, 1, 0)
	}
	handshake := append([]byte{2, 0, 0, byte(len(body))}, body...)
	return append([]byte{22, 3, 3, 0, byte(len(handshake))}, handshake...)
}

// fine is the reply of a server with nothing wrong.
func fine(hello clientHello) []byte {
	if hello.version == 0x0303 && hello.offers(0xc02f) {
		return serverHelloRecord(0x0303, 0xc02f, 0, true)
	}
	return alert
}

// fakeServer replies to each ClientHello with what reply returns, or hangs up if that's nil.
type fakeServer struct {
	addr     string
	reply    func(clientHello) []byte
	silent   func(clientHello) bool
	accepted atomic.Int64
}

func startFake(t *testing.T, s *fakeServer) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	s.addr = listener.Addr().String()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			s.accepted.Add(1)
			go func() {
				defer conn.Close()
				hello, ok := readClientHello(conn)
				if !ok {
					return
				}
				if s.silent != nil && s.silent(hello) {
					io.Copy(io.Discard, conn)
					return
				}
				if s.reply != nil {
					conn.Write(s.reply(hello))
				}
				time.Sleep(10 * time.Millisecond) // Closing at once can reset the connection before the client reads.
			}()
		}
	}()
}

func dialTo(address string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
}

func probeFake(t *testing.T, s *fakeServer) (map[string]robertparker.Finding, error) {
	t.Helper()
	startFake(t, s)
	d := robertparker.NewDomain("example.com")
	config := robertparker.WebConfig{DialContext: dialTo(s.addr), ProbeTimeout: 100 * time.Millisecond}
	err := robertparker.ProbeTLS(context.Background(), config, d, "example.com")
	return probeFindings(d), err
}

func TestProbeFakeServers(t *testing.T) {
	const (
		rc4    = 0x0005
		null   = 0x0001
		export = 0x0003
	)
	accepting := func(suite uint16) func(clientHello) []byte {
		return func(hello clientHello) []byte {
			if hello.version == 0x0303 && hello.offers(suite) && !hello.offers(0xc02f) {
				return serverHelloRecord(0x0303, suite, 0, true)
			}
			return fine(hello)
		}
	}
	tests := []struct {
		name     string
		reply    func(clientHello) []byte
		check    string
		severity robertparker.Severity
		message  string
	}{
		{"nothing wrong", fine, "", "", ""},
		{"TLS 1.3 only", func(clientHello) []byte { return alert }, "", "", ""},
		{"SSL 3.0", func(hello clientHello) []byte {
			if hello.version == 0x0300 {
				return serverHelloRecord(0x0300, 0x002f, 0, false)
			}
			return fine(hello)
		}, "tls-legacy", robertparker.SeverityWarning, "SSL 3.0"},
		{"answers with a lower version than it was offered", func(hello clientHello) []byte {
			if hello.version == 0x0302 || hello.version == 0x0301 {
				return serverHelloRecord(0x0301, 0x002f, 0, true)
			}
			return fine(hello)
		}, "tls-legacy", robertparker.SeverityWarning, "Accepts TLS 1.0, which"},
		{"NULL", accepting(null), "tls-cipher-broken", robertparker.SeverityFailure, "NULL"},
		{"export", accepting(export), "tls-cipher-broken", robertparker.SeverityFailure, "export"},
		{"RC4", accepting(rc4), "tls-cipher-broken", robertparker.SeverityFailure, "RC4"},
		{"3DES", accepting(0x000a), "tls-legacy", robertparker.SeverityWarning, "3DES"},
		{"RSA key exchange", accepting(0x002f), "tls-legacy", robertparker.SeverityWarning, "RSA"},
		{"CBC", accepting(0xc013), "tls-cipher-cbc", robertparker.SeverityInfo, "CBC"},
		{"compression", func(hello clientHello) []byte {
			if slices.Contains(hello.compression, 1) {
				return serverHelloRecord(0x0303, 0xc02f, 1, true)
			}
			return fine(hello)
		}, "tls-compression", robertparker.SeverityFailure, "compression"},
		{"no secure renegotiation", func(hello clientHello) []byte {
			if hello.version == 0x0303 && hello.offers(0xc02f) {
				return serverHelloRecord(0x0303, 0xc02f, 0, false)
			}
			return alert
		}, "tls-renegotiation", robertparker.SeverityWarning, "renegotiation"},
		{"split across two records", func(hello clientHello) []byte {
			record := serverHelloRecord(0x0303, 0xc02f, 0, false)
			if !hello.offers(0xc02f) {
				return alert
			}
			body := record[5:]
			first := append([]byte{22, 3, 3, 0, 10}, body[:10]...)
			second := append([]byte{22, 3, 3, 0, byte(len(body) - 10)}, body[10:]...)
			return append(first, second...)
		}, "tls-renegotiation", robertparker.SeverityWarning, "renegotiation"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, err := probeFake(t, &fakeServer{reply: tt.reply})
			if err != nil {
				t.Fatal(err)
			}
			if tt.check == "" {
				if len(found) != 0 {
					t.Errorf("found %+v", found)
				}
				return
			}
			f := found[tt.check]
			if f.Severity != tt.severity || !strings.Contains(f.Message, tt.message) {
				t.Errorf("got %+v, want %s %q", found, tt.severity, tt.message)
			}
		})
	}
}

// A server's choice only counts if it's something it was offered.
func TestProbeIgnoresASuiteThatWasNotOffered(t *testing.T) {
	found, err := probeFake(t, &fakeServer{reply: func(hello clientHello) []byte {
		if hello.offers(0xc02f) {
			return serverHelloRecord(0x0303, 0xc02f, 0, true)
		}
		return serverHelloRecord(0x0303, 0xc02f, 0, true)
	}})
	if err != nil {
		t.Fatal(err)
	}
	for check := range found {
		if strings.HasPrefix(check, "tls-cipher") {
			t.Errorf("found %+v", found)
		}
	}
}

func TestProbeGetsNoReply(t *testing.T) {
	silent := func(clientHello) bool { return true }
	garbage := func(clientHello) []byte { return []byte("HTTP/1.1 400 Bad Request\r\n\r\n") }
	tests := []struct {
		name   string
		server *fakeServer
	}{
		{"hangs up", &fakeServer{}},
		{"stays silent", &fakeServer{silent: silent}},
		{"isn't TLS", &fakeServer{reply: garbage}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, err := probeFake(t, tt.server)
			if err == nil {
				t.Error("no error")
			}
			if len(found) != 1 || found["tls-probe"].Severity != robertparker.SeverityUnknown {
				t.Errorf("got %+v", found)
			}
		})
	}
}

// Plenty of servers stay silent or hang up instead of sending an alert, which is still saying no.
func TestProbeOnlyTheOldOffersGetNoReply(t *testing.T) {
	found, err := probeFake(t, &fakeServer{
		silent: func(hello clientHello) bool { return hello.version != 0x0303 },
		reply:  fine,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Errorf("found %+v", found)
	}
}

func TestProbeConnectionFailure(t *testing.T) {
	t.Run("always", func(t *testing.T) {
		d := robertparker.NewDomain("example.com")
		config := robertparker.WebConfig{DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("refused")
		}}
		if err := robertparker.ProbeTLS(context.Background(), config, d, "example.com"); err == nil {
			t.Error("no error")
		}
		if found := probeFindings(d); found["tls-probe"].Severity != robertparker.SeverityUnknown {
			t.Errorf("got %+v", found)
		}
	})
	t.Run("once", func(t *testing.T) {
		s := &fakeServer{reply: fine}
		startFake(t, s)
		var dials atomic.Int64
		d := robertparker.NewDomain("example.com")
		config := robertparker.WebConfig{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if dials.Add(1) == 1 {
				return nil, errors.New("dropped")
			}
			return dialTo(s.addr)(ctx, network, addr)
		}}
		if err := robertparker.ProbeTLS(context.Background(), config, d, "example.com"); err != nil {
			t.Fatal(err)
		}
		if found := probeFindings(d); len(found) != 0 {
			t.Errorf("found %+v", found)
		}
	})
}

// A server that didn't get to reply because time ran out says nothing about the server.
func TestProbeOutOfTime(t *testing.T) {
	s := &fakeServer{silent: func(clientHello) bool { return true }}
	startFake(t, s)
	d := robertparker.NewDomain("example.com")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	config := robertparker.WebConfig{DialContext: dialTo(s.addr), ProbeTimeout: time.Second}
	if err := robertparker.ProbeTLS(ctx, config, d, "example.com"); err == nil {
		t.Error("no error")
	}
	if found := probeFindings(d); found["tls-probe"].Message != "Ran out of time probing the server." {
		t.Errorf("got %+v", found)
	}
}

// countedConn is a connection that says when it's closed.
type countedConn struct {
	net.Conn
	closed func()
}

func (c *countedConn) Close() error {
	c.closed()
	return c.Conn.Close()
}

func TestProbeIsGentle(t *testing.T) {
	s := &fakeServer{reply: fine}
	startFake(t, s)
	var mu sync.Mutex
	open, peak := 0, 0
	config := robertparker.WebConfig{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		open++
		peak = max(peak, open)
		mu.Unlock()
		conn, err := dialTo(s.addr)(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &countedConn{conn, func() {
			mu.Lock()
			defer mu.Unlock()
			open--
		}}, nil
	}}
	d := robertparker.NewDomain("example.com")
	if err := robertparker.ProbeTLS(context.Background(), config, d, "example.com"); err != nil {
		t.Fatal(err)
	}
	if got := s.accepted.Load(); got != 10 {
		t.Errorf("made %d connections", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if peak > 3 {
		t.Errorf("had %d connections at once", peak)
	}
}

func TestProbeIsOffByDefault(t *testing.T) {
	var probes atomic.Int64
	site := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(site.Close)
	d := robertparker.NewDomain("example.com")
	analyzer := robertparker.WebAnalyzer(robertparker.WebConfig{
		TLS: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			probes.Add(1)
			return dialTo(site.Listener.Addr().String())(ctx, network, addr)
		},
	}, nil)
	if err := analyzer(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if len(probeFindings(d)) != 0 {
		t.Errorf("got %+v", d.Findings)
	}
	if got := probes.Load(); got > 3 {
		t.Errorf("made %d connections", got)
	}
}

// Old versions, 3DES, and RSA key exchange are one choice, to support old devices. Counting each gave google.com an F.
func TestProbeLegacySupportCostsOnce(t *testing.T) {
	s := &fakeServer{reply: func(hello clientHello) []byte {
		switch {
		case hello.version != 0x0303:
			return serverHelloRecord(hello.version, 0x002f, 0, true)
		case hello.offers(0xc02f):
			return fine(hello)
		case hello.offers(0x000a) || hello.offers(0x002f):
			return serverHelloRecord(0x0303, hello.suites[0], 0, true)
		}
		return alert
	}}
	startFake(t, s)
	d := robertparker.NewDomain("example.com")
	d.Checked(robertparker.AreaTLS)
	config := robertparker.WebConfig{DialContext: dialTo(s.addr), ProbeTimeout: time.Second}
	if err := robertparker.ProbeTLS(context.Background(), config, d, "example.com"); err != nil {
		t.Fatal(err)
	}
	legacy := 0
	for _, f := range d.Findings {
		if f.Check == "tls-legacy" {
			legacy++
		}
	}
	if legacy != 3 {
		t.Errorf("got %d findings in %+v", legacy, d.Findings)
	}
	if got := robertparker.Grade(d); got != "B" {
		t.Errorf("got grade %q from %+v", got, d.Findings)
	}
}
