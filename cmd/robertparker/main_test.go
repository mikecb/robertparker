package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"testing"

	"github.com/mikecb/robertparker"
)

// runCLI runs the command with args and stdin, and returns its exit code, stdout, and stderr.
func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	return runCLIContext(t, context.Background(), stdin, args...)
}

func runCLIContext(t *testing.T, ctx context.Context, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(ctx, args, strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// lines returns n domains, one per line.
func lines(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "d%d.example.com\n", i)
	}
	return b.String()
}

// decode parses JSON Lines output into domains.
func decode(t *testing.T, out string) []robertparker.Domain {
	t.Helper()
	var domains []robertparker.Domain
	dec := json.NewDecoder(strings.NewReader(out))
	for dec.More() {
		var d robertparker.Domain
		if err := dec.Decode(&d); err != nil {
			t.Fatalf("decoding output: %v\n%s", err, out)
		}
		domains = append(domains, d)
	}
	return domains
}

func TestArgs(t *testing.T) {
	code, out, _ := runCLI(t, "", "WWW.Google.COM", "foo.appspot.com")
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	if n := strings.Count(out, "\n"); n != 2 {
		t.Errorf("want one JSON object per line, got %d lines:\n%s", n, out)
	}
	got := decode(t, out)
	if len(got) != 2 || got[0].FQDN != "google.com" || got[0].Secondary != "google" || got[1].Suffix != "appspot.com" {
		t.Errorf("unexpected output: %+v", got)
	}
	if got[0].Entropy == 0 {
		t.Error("entropy was not computed")
	}
}

func TestStdin(t *testing.T) {
	code, out, _ := runCLI(t, "# comment\n\n  google.com  \nexample.com\r\n")
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	got := decode(t, out)
	if len(got) != 2 || got[0].FQDN != "google.com" || got[1].FQDN != "example.com" {
		t.Errorf("want google.com and example.com, got %+v", got)
	}
}

func TestFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(path, []byte("example.com\ntest.google\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runCLI(t, "ignored.com", "-f", path, "google.com")
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	got := decode(t, out)
	if len(got) != 3 || got[0].FQDN != "google.com" || got[1].FQDN != "example.com" || got[2].FQDN != "test.google" {
		t.Errorf("want arguments then file, and stdin ignored, got %+v", got)
	}
}

func TestFileStdin(t *testing.T) {
	code, out, _ := runCLI(t, "example.com\n", "-f", "-")
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	if got := decode(t, out); len(got) != 1 || got[0].FQDN != "example.com" {
		t.Errorf("want example.com from stdin, got %+v", got)
	}
}

func TestPermute(t *testing.T) {
	code, out, _ := runCLI(t, "", "-permute", "example.com")
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	got := decode(t, out)
	want := robertparker.Permute(robertparker.NewDomain("example.com"))
	if len(got) != 1 || len(got[0].Permutations) != len(want) {
		t.Fatalf("want %d permutations, got %+v", len(want), got)
	}
}

func TestText(t *testing.T) {
	code, out, _ := runCLI(t, "", "-o", "text", "com", "a.b.example.com")
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("want header and 2 rows, got:\n%s", out)
	}
	if f := strings.Fields(lines[0]); len(f) != 6 || f[0] != "DOMAIN" || f[5] != "ENTROPY" {
		t.Errorf("unexpected header %q", lines[0])
	}
	if f := strings.Fields(lines[1]); len(f) != 6 || f[2] != "-" || f[3] != "-" || f[5] != "0.000" {
		t.Errorf("want dashes for empty columns and unsigned zero entropy, got %q", lines[1])
	}
	if f := strings.Fields(lines[2]); len(f) != 6 || f[2] != "example" || f[3] != "a.b" || f[4] != "true" {
		t.Errorf("unexpected row %q", lines[2])
	}
}

func TestTextPermute(t *testing.T) {
	code, out, _ := runCLI(t, "", "-o", "text", "-permute", "example.com")
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	want := robertparker.Permute(robertparker.NewDomain("example.com"))
	if len(lines) != len(want)+1 {
		t.Fatalf("want header and %d rows, got %d lines", len(want), len(lines))
	}
	if f := strings.Fields(lines[1]); len(f) != 4 || f[0] != "example.com" || f[1] != want[0].Fuzzer || f[3] != want[0].ASCII {
		t.Errorf("unexpected row %q", lines[1])
	}
}

func TestPretty(t *testing.T) {
	code, out, _ := runCLI(t, "", "-o", "pretty", "example.com")
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	if !strings.Contains(out, "\n  \"FQDN\": \"example.com\",\n") {
		t.Errorf("want indented JSON, got:\n%s", out)
	}
}

func TestErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
		msg  string
	}{
		{"unknown format", []string{"-o", "yaml", "example.com"}, 2, "unknown output format"},
		{"unknown flag", []string{"-nope"}, 2, "flag provided but not defined"},
		{"missing file", []string{"-f", filepath.Join(t.TempDir(), "missing.txt")}, 1, "missing.txt"},
		{"zero workers", []string{"-workers", "0", "example.com"}, 2, "-workers must be at least 1"},
	}
	for _, tt := range tests {
		code, out, errOut := runCLI(t, "", tt.args...)
		if code != tt.code || out != "" || !strings.Contains(errOut, tt.msg) {
			t.Errorf("%s: got exit %d, stdout %q, stderr %q", tt.name, code, out, errOut)
		}
	}
}

func TestHelp(t *testing.T) {
	code, out, errOut := runCLI(t, "", "-h")
	if code != 0 || out != "" || !strings.HasPrefix(errOut, "Usage: robertparker") {
		t.Errorf("got exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestWorkersSameOutput(t *testing.T) {
	in := lines(300)
	_, one, _ := runCLI(t, in, "-permute", "-workers", "1")
	code, many, _ := runCLI(t, in, "-permute", "-workers", "16")
	if code != 0 || one == "" || one != many {
		t.Errorf("output with 16 workers differs from 1 worker (exit %d)", code)
	}
}

func TestUnordered(t *testing.T) {
	code, out, _ := runCLI(t, lines(300), "-unordered", "-workers", "16")
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	var got []string
	for _, d := range decode(t, out) {
		got = append(got, d.FQDN)
	}
	sort.Strings(got)
	want := strings.Fields(lines(300))
	sort.Strings(want)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("unordered output is not the same set of domains as the input: got %d", len(got))
	}
}

func TestLargeText(t *testing.T) {
	// More rows than one text block, so output is written in several blocks with one header.
	code, out, _ := runCLI(t, lines(2500), "-o", "text")
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	rows := strings.Split(strings.TrimSpace(out), "\n")
	headers := 0
	for _, r := range rows {
		if strings.HasPrefix(r, "DOMAIN ") {
			headers++
		}
	}
	if len(rows) != 2501 || headers != 1 || !strings.HasPrefix(rows[0], "DOMAIN ") {
		t.Errorf("want 1 header and 2500 rows, got %d lines and %d headers", len(rows), headers)
	}
	if !strings.HasPrefix(rows[2500], "d2499.example.com ") {
		t.Errorf("last row %q, want d2499.example.com", rows[2500])
	}
}

func TestInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, _, errOut := runCLIContext(t, ctx, lines(1000))
	if code != 130 || !strings.Contains(errOut, "interrupted") {
		t.Errorf("got exit %d, stderr %q, want 130 and interrupted", code, errOut)
	}
}

// errReader returns its data, then an error.
type errReader struct{ data *strings.Reader }

func (r errReader) Read(p []byte) (int, error) {
	if r.data.Len() == 0 {
		return 0, fmt.Errorf("disk on fire")
	}
	return r.data.Read(p)
}

func TestReadError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"-f", "-"}, errReader{strings.NewReader("example.com\n")}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "disk on fire") {
		t.Errorf("got exit %d, stderr %q, want 1 and the read error", code, stderr.String())
	}
	if got := decode(t, stdout.String()); len(got) != 1 || got[0].FQDN != "example.com" {
		t.Errorf("want domains read before the error to be output, got %+v", got)
	}
}

func TestTuneGC(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(100))

	t.Setenv("GOGC", "50")
	debug.SetGCPercent(50)
	tuneGC()
	if got := debug.SetGCPercent(100); got != 50 {
		t.Errorf("with GOGC set, GC percent is %d, want it left at 50", got)
	}

	os.Unsetenv("GOGC")
	tuneGC()
	if got := debug.SetGCPercent(100); got != gcPercent {
		t.Errorf("with GOGC unset, GC percent is %d, want %d", got, gcPercent)
	}
}
