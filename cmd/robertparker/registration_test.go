package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mikecb/robertparker"
)

// fakeRegistrations answers registration lookups from a map.
type fakeRegistrations map[string]*robertparker.Registration

func (f fakeRegistrations) Lookup(_ context.Context, domain string) (*robertparker.Registration, error) {
	if domain == "fails.com" {
		return nil, errors.New("rdap broke")
	}
	return f[domain], nil
}

func useRegistrations(t *testing.T, f robertparker.RegistrationSource) {
	t.Helper()
	old := registrations
	registrations = f
	t.Cleanup(func() { registrations = old })
}

func goodRegistrations() fakeRegistrations {
	return fakeRegistrations{
		"example.com": {Registrar: "Brand Registrar", RegistrarID: "1", Registered: time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC)},
		"exmaple.com": {Registrar: "Other Registrar", RegistrarID: "2", Registered: time.Date(2001, 1, 2, 0, 0, 0, 0, time.UTC)},
		"example.net": {Registrar: "Brand Registrar", RegistrarID: "1", Registered: time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC)},
	}
}

func TestRegistrationJSON(t *testing.T) {
	useLookalikes(t, goodLookalikes())
	useRegistrations(t, goodRegistrations())
	code, out, errOut := runCLI(t, "", "-rate", "0", "-registration", "example.com")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	got := decode(t, out)
	if len(got) != 1 || len(got[0].Lookalikes) != 2 {
		t.Fatalf("-registration should imply -lookup, got %+v", got)
	}
	first, second := got[0].Lookalikes[0], got[0].Lookalikes[1]
	if first.ASCII != "exmaple.com" || first.Suspicion != robertparker.SuspicionMedium || first.Registrar != "Other Registrar" {
		t.Errorf("first: %+v", first)
	}
	if second.ASCII != "example.net" || second.Suspicion != robertparker.SuspicionLow || !second.SameRegistrar {
		t.Errorf("second: %+v", second)
	}
}

func TestRegistrationText(t *testing.T) {
	useLookalikes(t, goodLookalikes())
	useRegistrations(t, goodRegistrations())
	code, out, _ := runCLI(t, "", "-rate", "0", "-registration", "-o", "text", "example.com")
	rows := strings.Split(strings.TrimSpace(out), "\n")
	if code != 0 || len(rows) != 3 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if f := strings.Fields(rows[0]); strings.Join(f, " ") != "DOMAIN SUSPICION LOOKALIKE ASCII REGISTRAR REGISTERED REASONS" {
		t.Errorf("unexpected header %q", rows[0])
	}
	for _, want := range []string{"medium", "Other Registrar", "2001-01-02", "can receive mail"} {
		if !strings.Contains(rows[1], want) {
			t.Errorf("row %q is missing %q", rows[1], want)
		}
	}
}

func TestSuspiciousOnly(t *testing.T) {
	useLookalikes(t, goodLookalikes())
	useRegistrations(t, goodRegistrations())
	_, out, _ := runCLI(t, "", "-rate", "0", "-suspicious", "example.com")
	got := decode(t, out)
	if len(got) != 1 || len(got[0].Lookalikes) != 1 || got[0].Lookalikes[0].ASCII != "exmaple.com" {
		t.Errorf("want only the medium one, got %+v", got)
	}
}

func TestRegistrationFailure(t *testing.T) {
	useLookalikes(t, &fakeLookalikes{hosts: map[string][]string{"exmaple.com": {"192.0.2.1"}, "fails.com": {"192.0.2.2"}}})
	useRegistrations(t, fakeRegistrations{})
	code, _, errOut := runCLI(t, "", "-rate", "0", "-registration", "-o", "text", "failz.com")
	if code != 1 || !strings.Contains(errOut, "rdap broke") {
		t.Errorf("got exit %d, stderr %q", code, errOut)
	}
}

func TestRegistrationOffByDefault(t *testing.T) {
	useLookalikes(t, goodLookalikes())
	useRegistrations(t, goodRegistrations())
	if _, out, _ := runCLI(t, "", "-rate", "0", "-lookup", "example.com"); strings.Contains(out, "Suspicion") || strings.Contains(out, "Registrar") {
		t.Errorf("got %s", out)
	}
}
