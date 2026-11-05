package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mikecb/robertparker"
)

func decodeMatches(t *testing.T, out string) []robertparker.BrandMatch {
	t.Helper()
	var matches []robertparker.BrandMatch
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var m robertparker.BrandMatch
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		matches = append(matches, m)
	}
	return matches
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMatchFile(t *testing.T) {
	names := writeFile(t, "names.txt", "# comment\nexample.net\npaypal-login.com\nwww.paypal-login.com\nmetanask.cyou\nlogin.paypal.com\n")
	code, out, errOut := runCLI(t, "", "-match", names, "paypal.com", "metamask.io")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	got := decodeMatches(t, out)
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Brand != "paypal.com" || got[0].Fuzzer != robertparker.MatchWord || got[0].ASCII != "paypal-login.com" {
		t.Errorf("got %+v", got[0])
	}
	if got[1].Brand != "metamask.io" || got[1].Fuzzer != robertparker.MatchTypo || got[1].Suspicion != "" {
		t.Errorf("got %+v", got[1])
	}
}

func TestMatchStdin(t *testing.T) {
	brands := writeFile(t, "brands.txt", "paypal.com\n")
	code, out, errOut := runCLI(t, "paypal-login.com\n", "-match", "-", "-f", brands, "-o", "text")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if want := brandHeader + "\n-\tpaypal.com\tword\t-\tpaypal-login.com\tpaypal-login.com\t-\t-\n"; out != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

func TestMatchOwned(t *testing.T) {
	names := writeFile(t, "names.txt", "s3.amazonaws.com\namazon-login.com\n")
	owned := writeFile(t, "owned.txt", "# Also Amazon's.\namazonaws.com\n")
	code, out, errOut := runCLI(t, "", "-match", names, "-owned", owned, "amazon.com")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if got := decodeMatches(t, out); len(got) != 1 || got[0].ASCII != "amazon-login.com" {
		t.Errorf("got %+v", got)
	}
}

func TestMatchRanked(t *testing.T) {
	useLookalikes(t, goodLookalikes())
	registered := time.Now().Add(-24 * time.Hour)
	useRegistrations(t, fakeRegistrations{
		"example.com": {Registrar: "Brand Registrar", RegistrarID: "1", Registered: time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC)},
		"example.net": {Registrar: "Brand Registrar", RegistrarID: "1", Registered: time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC)},
		"exmaple.com": {Registrar: "Other Registrar", RegistrarID: "2", Registered: registered},
	})
	names := writeFile(t, "names.txt", "exmaple.com\nexample.net\n")

	code, out, errOut := runCLI(t, "", "-rate", "0", "-registration", "-workers", "1", "-match", names, "example.com")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	got := decodeMatches(t, out)
	if len(got) != 2 || got[0].Suspicion != robertparker.SuspicionHigh || got[1].Suspicion != robertparker.SuspicionLow {
		t.Fatalf("got %+v", got)
	}

	code, out, errOut = runCLI(t, "", "-rate", "0", "-suspicious", "-match", names, "example.com")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if got := decodeMatches(t, out); len(got) != 1 || got[0].ASCII != "exmaple.com" {
		t.Errorf("-suspicious: got %+v", got)
	}
}

func TestMatchRankFailureIsReported(t *testing.T) {
	useLookalikes(t, &fakeLookalikes{hosts: map[string][]string{"fails.com": {"192.0.2.1"}}})
	useRegistrations(t, fakeRegistrations{"example.com": {Registrar: "Brand"}})
	names := writeFile(t, "names.txt", "example.fails.com\n")
	code, out, errOut := runCLI(t, "", "-rate", "0", "-registration", "-match", names, "example.com")
	if code != 1 || !strings.Contains(errOut, "rdap broke") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if got := decodeMatches(t, out); len(got) != 1 || got[0].Suspicion != robertparker.SuspicionUnknown {
		t.Errorf("the match should still be shown: got %+v", got)
	}
}

func TestBrandFlagConflicts(t *testing.T) {
	for _, args := range [][]string{
		{"-watch", "-permute", "example.com"},
		{"-watch", "-lookup", "example.com"},
		{"-watch", "-records", "example.com"},
		{"-watch", "-checks", "dns", "example.com"},
		{"-watch", "-match", "names.txt", "example.com"},
		{"-owned", "owned.txt", "example.com"},
		{"-match", "-"},
		{"-match", "-", "-f", "-"},
	} {
		if code, _, _ := runCLI(t, "", args...); code != 2 {
			t.Errorf("%q: exit %d", args, code)
		}
	}
}

func TestMatchMissingFiles(t *testing.T) {
	names := writeFile(t, "names.txt", "")
	for _, args := range [][]string{
		{"-match", filepath.Join(t.TempDir(), "missing"), "example.com"},
		{"-match", names, "-owned", filepath.Join(t.TempDir(), "missing"), "example.com"},
	} {
		if code, _, errOut := runCLI(t, "", args...); code != 1 || errOut == "" {
			t.Errorf("%q: exit %d: %s", args, code, errOut)
		}
	}
}

// useLog makes a certificate log that holds a full tile, then gains another one once a client has looked.
func useLog(t *testing.T, names ...string) {
	t.Helper()
	var server *httptest.Server
	var looks atomic.Int32
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/list.json":
			fmt.Fprintf(w, `{"operators": [{"tiled_logs": [{"description": "Test log", "monitoring_url": %q, "state": {"usable": {}}, "temporal_interval": {"start_inclusive": "2020-01-01T00:00:00Z", "end_exclusive": "2099-01-01T00:00:00Z"}}]}]}`, server.URL+"/")
		case "/checkpoint":
			size := 256
			if looks.Add(1) > 2 {
				size = 512
			}
			fmt.Fprintf(w, "test.example/log\n%d\nAAAA\n\n", size)
		case "/tile/names/000":
		case "/tile/names/001":
			for i := range 256 {
				name := "example.net"
				if i < len(names) {
					name = names[i]
				}
				fmt.Fprintf(w, `{"Timestamp": 1753375092043, "DNS": [%q]}`+"\n", name)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	old := certificates
	certificates = robertparker.CTReader{List: server.URL + "/list.json", Poll: time.Millisecond}
	t.Cleanup(func() { certificates = old })
}

func TestWatch(t *testing.T) {
	useLog(t, "paypal-login.com", "www.paypal-login.com", "example.org", "paypal.xyz")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	code, out, errOut := runCLIContext(t, ctx, "", "-watch", "paypal.com")
	if code != 0 {
		t.Fatalf("a watch ending is what's meant to happen, but got exit %d: %s", code, errOut)
	}
	if !strings.Contains(errOut, "following Test log") {
		t.Errorf("stderr: %q", errOut)
	}
	got := decodeMatches(t, out)
	if len(got) != 2 || got[0].ASCII != "paypal-login.com" || got[1].Fuzzer != robertparker.MatchOtherSuffix {
		t.Fatalf("got %+v", got)
	}
	if got[0].Source != "Test log" || got[0].Seen.UnixMilli() != 1753375092043 {
		t.Errorf("got %+v", got[0])
	}
}

func TestWatchTimeout(t *testing.T) {
	useLog(t)
	code, _, errOut := runCLI(t, "", "-watch", "-timeout", "50ms", "paypal.com")
	if code != 0 {
		t.Errorf("exit %d: %s", code, errOut)
	}
}

func TestWatchWithoutLogs(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	old := certificates
	certificates = robertparker.CTReader{List: server.URL}
	defer func() { certificates = old }()
	if code, _, errOut := runCLI(t, "", "-watch", "paypal.com"); code != 1 || !strings.Contains(errOut, "log list") {
		t.Errorf("exit %d: %s", code, errOut)
	}
}
