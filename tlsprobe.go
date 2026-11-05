package robertparker

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

//The TLS prober. A normal connection only shows the best thing a server will do, so a server that also accepts TLS 1.0
//or RC4 looks fine. Finding those means offering them, and Go's crypto/tls can't offer most of them, so this builds the
//ClientHello by hand. It only reads the server's reply and hangs up, so no handshake ever finishes.

const (
	// CheckTLSProbe is the name of the prober in lists of checks. Its findings are in AreaTLS.
	CheckTLSProbe = "tls-probe"

	probeTimeout = 3 * time.Second
	maxTLSRecord = 1 << 15

	// probeConcurrency is how many connections a server gets at once. More, and some start dropping them, as badssl.com
	// did at 10.
	probeConcurrency = 3

	versionSSL30 = 0x0300
	versionTLS10 = 0x0301
	versionTLS11 = 0x0302
	versionTLS12 = 0x0303

	recordAlert     = 21
	recordHandshake = 22

	handshakeClientHello = 1
	handshakeServerHello = 2

	compressionNull    = 0
	compressionDeflate = 1

	extensionServerName          = 0
	extensionSupportedGroups     = 10
	extensionECPointFormats      = 11
	extensionSignatureAlgorithms = 13
	extensionRenegotiationInfo   = 0xff01
)

// oldVersions are the protocol versions that shouldn't be accepted.
var oldVersions = []struct {
	version uint16
	name    string
}{
	{versionSSL30, "SSL 3.0"},
	{versionTLS10, "TLS 1.0"},
	{versionTLS11, "TLS 1.1"},
}

// cipherGroups are the kinds of cipher suite to look for. tls-legacy is one check with the old versions, because those
// are all one choice, to support old devices, so a site pays once. One ClientHello offers a whole group, since what matters is
// whether the server accepts any of it.
var cipherGroups = []struct {
	name     string
	check    string
	severity Severity
	suites   []uint16
}{
	{"NULL ciphers, which don't encrypt", "tls-cipher-broken", SeverityFailure, []uint16{0x0001, 0x0002, 0x003b, 0xc006, 0xc010, 0xc00b, 0xc001, 0x0000}},
	{"export ciphers, which are short enough to break", "tls-cipher-broken", SeverityFailure, []uint16{0x0003, 0x0006, 0x0008, 0x000b, 0x000e, 0x0011, 0x0014, 0x0017, 0x0019, 0x0062, 0x0064}},
	{"RC4, which is broken", "tls-cipher-broken", SeverityFailure, []uint16{0x0004, 0x0005, 0xc007, 0xc011, 0x0018, 0xc002, 0xc00c}},
	{"3DES, which has a 64-bit block size", "tls-legacy", SeverityWarning, []uint16{0x000a, 0x0016, 0x0013, 0xc008, 0xc012, 0xc003, 0xc00d}},
	{"RSA key exchange, which isn't forward secret", "tls-legacy", SeverityWarning, []uint16{0x002f, 0x0035, 0x003c, 0x003d, 0x009c, 0x009d}},
	// Only information, since it's more than half of the sites sampled, and the problems with CBC are mostly worked around.
	{"CBC ciphers, which aren't AEAD", "tls-cipher-cbc", SeverityInfo, []uint16{0xc009, 0xc00a, 0xc013, 0xc014, 0xc023, 0xc024, 0xc027, 0xc028, 0x0033, 0x0039, 0x0067, 0x006b}},
}

// modernSuites are what a server with nothing wrong would choose.
var modernSuites = []uint16{0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9, 0x009e, 0x009f, 0xccaa}

// everySuite is a ClientHello for finding out about a version, where the cipher doesn't matter.
var everySuite = func() []uint16 {
	suites := slices.Clone(modernSuites)
	for _, group := range cipherGroups {
		suites = append(suites, group.suites...)
	}
	return suites
}()

// buildClientHello returns a ClientHello for one TLS record. It doesn't offer TLS 1.3, which would need more extensions
// and has nothing to find. version is the highest version it offers.
func buildClientHello(host string, version uint16, suites []uint16, compression []byte) ([]byte, error) {
	if len(host) > 255 {
		return nil, errors.New("host name too long")
	}
	var body []byte
	body = binary.BigEndian.AppendUint16(body, version)
	random := make([]byte, 32)
	rand.Read(random)
	body = append(body, random...)
	body = append(body, 0) // No session ID.
	body = binary.BigEndian.AppendUint16(body, uint16(2*len(suites)))
	for _, suite := range suites {
		body = binary.BigEndian.AppendUint16(body, suite)
	}
	body = append(body, byte(len(compression)))
	body = append(body, compression...)

	// Every version gets extensions, even SSL 3.0, which came before them, because a server hosting several sites needs
	// the name to find the right one, and anything that doesn't understand them ignores them.
	var extensions []byte
	name := append([]byte{0}, binary.BigEndian.AppendUint16(nil, uint16(len(host)))...)
	name = append(name, host...)
	extensions = appendExtension(extensions, extensionServerName, append(binary.BigEndian.AppendUint16(nil, uint16(len(name))), name...))
	extensions = appendExtension(extensions, extensionSupportedGroups, []byte{0, 6, 0, 29, 0, 23, 0, 24})
	extensions = appendExtension(extensions, extensionECPointFormats, []byte{1, 0})
	extensions = appendExtension(extensions, extensionSignatureAlgorithms, []byte{
		0, 16, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x02, 0x01, 0x02, 0x03,
	})
	extensions = appendExtension(extensions, extensionRenegotiationInfo, []byte{0})
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)

	handshake := []byte{handshakeClientHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	recordVersion := uint16(versionTLS10) // What clients send here, because some servers refuse anything newer.
	if version == versionSSL30 {
		recordVersion = versionSSL30
	}
	record := []byte{recordHandshake}
	record = binary.BigEndian.AppendUint16(record, recordVersion)
	record = binary.BigEndian.AppendUint16(record, uint16(len(handshake)))
	return append(record, handshake...), nil
}

// appendExtension adds one extension to a ClientHello.
func appendExtension(extensions []byte, kind uint16, data []byte) []byte {
	extensions = binary.BigEndian.AppendUint16(extensions, kind)
	extensions = binary.BigEndian.AppendUint16(extensions, uint16(len(data)))
	return append(extensions, data...)
}

// serverHello is what a server chose.
type serverHello struct {
	version       uint16
	suite         uint16
	compression   byte
	renegotiation bool //It supports secure renegotiation.
}

// readServerHello reads a server's first message. It returns nil if the server said no, with an alert, and an error
// if what it sent isn't TLS.
func readServerHello(r io.Reader) (*serverHello, error) {
	var handshake []byte
	for {
		var header [5]byte
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return nil, err
		}
		size := int(binary.BigEndian.Uint16(header[3:]))
		if header[1] != 3 || size > maxTLSRecord {
			return nil, errors.New("not a TLS record")
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
		switch header[0] {
		case recordAlert:
			return nil, nil
		case recordHandshake:
		default:
			return nil, errors.New("not a TLS handshake")
		}
		handshake = append(handshake, payload...)
		if len(handshake) < 4 {
			continue
		}
		if handshake[0] != handshakeServerHello {
			return nil, errors.New("not a ServerHello")
		}
		length := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if length > maxTLSRecord {
			return nil, errors.New("ServerHello too long")
		}
		if len(handshake) >= 4+length {
			return parseServerHello(handshake[4 : 4+length])
		}
	}
}

// parseServerHello parses the body of a ServerHello.
func parseServerHello(body []byte) (*serverHello, error) {
	bad := errors.New("ServerHello cut off")
	if len(body) < 35 {
		return nil, bad
	}
	hello := &serverHello{version: binary.BigEndian.Uint16(body)}
	rest := body[34:]
	sessionID := int(body[34])
	if len(rest) < 1+sessionID+3 {
		return nil, bad
	}
	rest = rest[1+sessionID:]
	hello.suite = binary.BigEndian.Uint16(rest)
	hello.compression = rest[2]
	rest = rest[3:]
	if len(rest) < 2 {
		return hello, nil // Extensions are optional.
	}
	rest = rest[2:]
	for len(rest) >= 4 {
		kind, size := binary.BigEndian.Uint16(rest), int(binary.BigEndian.Uint16(rest[2:]))
		if len(rest) < 4+size {
			return nil, bad
		}
		hello.renegotiation = hello.renegotiation || kind == extensionRenegotiationInfo
		rest = rest[4+size:]
	}
	return hello, nil
}

// isOrAre returns the verb for count things.
func isOrAre(count int) string {
	if count == 1 {
		return "is"
	}
	return "are"
}

// probeResult is how a server replied to one ClientHello.
type probeResult struct {
	hello   *serverHello //What it chose, or nil if it said no.
	replied bool         //It said something, even if only no.
	err     error        //Couldn't connect.
}

// offer sends one ClientHello, and reads the reply. A server that hangs up or stays silent is saying no as well, since
// plenty of servers do that instead of sending an alert.
func (w *webChecker) offer(ctx context.Context, host string, version uint16, suites []uint16, compression []byte) probeResult {
	hello, err := buildClientHello(host, version, suites, compression)
	if err != nil {
		return probeResult{err: err}
	}
	var result probeResult
	err = w.limiter.Do(ctx, func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, w.config.ProbeTimeout)
		defer cancel()
		dial := w.config.DialContext
		if dial == nil {
			dial = (&net.Dialer{}).DialContext
		}
		conn, err := dial(ctx, "tcp", net.JoinHostPort(host, "443"))
		if err != nil {
			return err
		}
		defer conn.Close()
		if deadline, ok := ctx.Deadline(); ok {
			conn.SetDeadline(deadline)
		}
		stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
		defer stop()
		if _, err := conn.Write(hello); err != nil {
			return nil
		}
		reply, err := readServerHello(conn)
		if err == nil {
			result = probeResult{hello: reply, replied: true}
		}
		return nil
	})
	if err != nil {
		return probeResult{err: err}
	}
	return result
}

// accepted reports whether the server took what was offered, at or below version.
func (r probeResult) accepted(version uint16, suites []uint16) bool {
	return r.hello != nil && r.hello.version <= version && slices.Contains(suites, r.hello.suite)
}

// probeTLS offers a server what it shouldn't accept, a few at a time, so that a server that stays silent doesn't take
// as long as all of the timeouts added up.
//
// The first offer is a reasonable one, which shows that the rest can be believed: a server that doesn't reply to it says
// nothing by not replying to them.
func (w *webChecker) probeTLS(ctx context.Context, host string) error {
	type probe struct {
		version     uint16
		suites      []uint16
		compression []byte
	}
	probes := []probe{{versionTLS12, slices.Concat(modernSuites, everySuite), []byte{compressionDeflate, compressionNull}}}
	for _, old := range oldVersions {
		probes = append(probes, probe{version: old.version, suites: everySuite, compression: []byte{compressionNull}})
	}
	for _, group := range cipherGroups {
		probes = append(probes, probe{version: versionTLS12, suites: group.suites, compression: []byte{compressionNull}})
	}

	results := make([]probeResult, len(probes))
	slots := make(chan struct{}, probeConcurrency)
	var wait sync.WaitGroup
	for i, p := range probes {
		wait.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			results[i] = w.offer(ctx, host, p.version, p.suites, p.compression)
			if results[i].err != nil { // One dropped connection shouldn't cost a domain its grade.
				results[i] = w.offer(ctx, host, p.version, p.suites, p.compression)
			}
		})
	}
	wait.Wait()

	deadline, limited := ctx.Deadline()
	if ctx.Err() != nil || limited && !time.Now().Before(deadline) {
		w.addTLS("tls-probe", SeverityUnknown, stdTLS, "Ran out of time probing the server.")
		return fmt.Errorf("ran out of time probing %s", host)
	}
	for _, r := range results {
		if r.err != nil {
			w.addTLS("tls-probe", SeverityUnknown, stdTLS, fmt.Sprintf("Couldn't connect to %s to probe it: %v", host, r.err))
			return fmt.Errorf("probing %s: %w", host, r.err)
		}
	}
	first, results := results[0], results[1:]
	if !first.replied {
		w.addTLS("tls-probe", SeverityUnknown, stdTLS, fmt.Sprintf("%s didn't reply to the probes.", host))
		return fmt.Errorf("no reply to the probes from %s", host)
	}
	if first.hello != nil {
		if first.hello.compression != compressionNull {
			w.addTLS("tls-compression", SeverityFailure, stdTLS, "Accepts TLS compression, which allows the CRIME attack.")
		}
		if !first.hello.renegotiation {
			w.addTLS("tls-renegotiation", SeverityWarning, "RFC 5746", "Doesn't support secure renegotiation.")
		}
	}

	var versions []string
	for i, old := range oldVersions {
		if results[i].hello != nil && results[i].hello.version == old.version {
			versions = append(versions, old.name)
		}
	}
	// A warning, because modern clients refuse these versions, so this only reaches old devices. Sites keep them for those
	// on purpose, including google.com and cloudflare.com, and a failure would give them an F, which says nothing.
	if len(versions) > 0 {
		w.addTLS("tls-legacy", SeverityWarning, "RFC 8996", fmt.Sprintf("Accepts %s, which %s deprecated.", strings.Join(versions, " and "), isOrAre(len(versions))))
	}
	results = results[len(oldVersions):]
	for i, group := range cipherGroups {
		if results[i].accepted(versionTLS12, group.suites) {
			w.addTLS(group.check, group.severity, stdTLS, "Accepts "+group.name+".")
		}
	}
	return nil
}
