package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mikecb/robertparker"
)

// runCLI runs the command with args and stdin, and returns its exit code, stdout, and stderr.
func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
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
