package main

import (
	"context"
	"net"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// startDNS runs a UDP DNS server that gives every A query one address, and nothing for anything else.
func TestChecksDNS(t *testing.T) {
	// Every lookup fails, which is enough to show that the check runs, and uses -resolver.
	address := startDNS(t, dnsmessage.RCodeServerFailure)
	var stdout, stderr strings.Builder
	code := run(context.Background(), []string{"-checks", "dns", "-resolver", address, "example.com"}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Errorf("got exit code %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"Area":"dns"`) || !strings.Contains(stdout.String(), `"Check":"dns-zone"`) {
		t.Errorf("got %s", stdout.String())
	}
}

func TestChecksDNSForAMissingDomain(t *testing.T) {
	address := startDNS(t, dnsmessage.RCodeNameError)
	var stdout, stderr strings.Builder
	code := run(context.Background(), []string{"-checks", "dns", "-resolver", address, "example.com"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Errorf("got exit code %d, stderr %q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), `"Grade"`) {
		t.Errorf("graded a zone that doesn't exist: %s", stdout.String())
	}
}

func startDNS(t *testing.T, rcode dnsmessage.RCode) string {
	t.Helper()
	packets, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { packets.Close() })
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, from, err := packets.ReadFrom(buffer)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buffer[:n]) != nil || len(query.Questions) != 1 {
				continue
			}
			reply := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RCode: rcode}, Questions: query.Questions}
			if q := query.Questions[0]; q.Type == dnsmessage.TypeA && rcode == dnsmessage.RCodeSuccess {
				reply.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET},
					Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 7}},
				}}
			}
			if packed, err := reply.Pack(); err == nil {
				packets.WriteTo(packed, from)
			}
		}
	}()
	return packets.LocalAddr().String()
}

func TestRecordsJSON(t *testing.T) {
	code, out, errOut := runCLI(t, "", "-rate", "0", "-records", "-resolver", startDNS(t, dnsmessage.RCodeSuccess), "example.com")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	got := decode(t, out)
	if len(got) != 1 || len(got[0].Records["A"]) != 1 || got[0].Records["A"][0] != "192.0.2.7" {
		t.Errorf("got %+v", got)
	}
}

func TestRecordsText(t *testing.T) {
	code, out, _ := runCLI(t, "", "-rate", "0", "-records", "-o", "text", "-resolver", startDNS(t, dnsmessage.RCodeSuccess), "example.com")
	rows := strings.Split(strings.TrimSpace(out), "\n")
	if code != 0 || len(rows) != 2 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if f := strings.Fields(rows[1]); strings.Join(f, " ") != "example.com A 192.0.2.7" {
		t.Errorf("unexpected row %q", rows[1])
	}
}

func TestRecordsFailure(t *testing.T) {
	code, _, errOut := runCLI(t, "", "-rate", "0", "-records", "-resolver", startDNS(t, dnsmessage.RCodeServerFailure), "example.com")
	if code != 1 || !strings.Contains(errOut, "record lookups failed") {
		t.Errorf("got exit %d, stderr %q", code, errOut)
	}
}

func TestRecordsWithOtherViews(t *testing.T) {
	if code, _, errOut := runCLI(t, "", "-records", "-permute", "-o", "text", "example.com"); code != 2 || !strings.Contains(errOut, "not both") {
		t.Errorf("got exit %d, stderr %q", code, errOut)
	}
	code, out, _ := runCLI(t, "", "-rate", "0", "-records", "-permute", "-resolver", startDNS(t, dnsmessage.RCodeSuccess), "example.com")
	if got := decode(t, out); code != 0 || len(got) != 1 || len(got[0].Permutations) == 0 || len(got[0].Records) == 0 {
		t.Errorf("exit %d: JSON should hold both", code)
	}
}

func TestRecordsOffByDefault(t *testing.T) {
	if _, out, _ := runCLI(t, "", "example.com"); strings.Contains(out, "Records") {
		t.Errorf("got %s", out)
	}
}
