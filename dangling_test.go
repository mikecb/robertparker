package robertparker_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mikecb/robertparker"
	"golang.org/x/net/dns/dnsmessage"
)

const nameError = dnsmessage.RCodeNameError

// danglingZone is healthyZone, with names pointing to targets that don't exist.
func danglingZone(targets map[string]string) *dnsServer {
	s := &dnsServer{answers: healthyZone(), rcodes: map[string]dnsmessage.RCode{}}
	for host, target := range targets {
		key := host + ".example.com. TypeA"
		s.answers[key] = []dnsmessage.ResourceBody{&dnsmessage.CNAMEResource{CNAME: name(target)}}
		s.rcodes[key] = nameError
	}
	return s
}

func TestDanglingCNAMEs(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		gone     string //A name that doesn't exist either.
		severity robertparker.Severity
		message  string
		grade    string
	}{
		{"domain that isn't registered", "www.long-gone.com.", "long-gone.com. TypeNS", robertparker.SeverityFailure, "doesn't seem to be registered", "D"},
		{"Azure", "gone.azurewebsites.net.", "", robertparker.SeverityFailure, "anyone can sign up", "D"},
		{"Azure region", "gone.eastus.cloudapp.azure.com.", "", robertparker.SeverityFailure, "anyone can sign up", "D"},
		{"Traffic Manager", "gone.trafficmanager.net.", "", robertparker.SeverityFailure, "anyone can sign up", "D"},
		{"Elastic Beanstalk", "gone.us-west-2.elasticbeanstalk.com.", "", robertparker.SeverityFailure, "anyone can sign up", "D"},
		{"Elastic Beanstalk name that's generated", "gone.bhjaevbknp.us-west-2.elasticbeanstalk.com.", "", robertparker.SeverityWarning, "if the provider lets", "A"},
		{"load balancer name that's generated", "internal-gone-762756181.us-east-1.elb.amazonaws.com.", "", robertparker.SeverityWarning, "if the provider lets", "A"},
		{"provider that's still there", "customer.provider.example.", "", robertparker.SeverityWarning, "if the provider lets", "A"},
		{"under the domain itself", "old.example.com.", "", robertparker.SeverityInfo, "only out of date", "A"},
		{"on a TLD that doesn't exist", "www.long-gone.notatld.", "", robertparker.SeverityWarning, "if the provider lets", "A"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := danglingZone(map[string]string{"blog": tt.target})
			if tt.gone != "" {
				s.rcodes[tt.gone] = nameError
			}
			d, err := checkDNS(t, s)
			if err != nil {
				t.Fatal(err)
			}
			if got := severities(d)["dns-dangling"]; got != tt.severity {
				t.Errorf("got %q, want %q, in %+v", got, tt.severity, d.Findings)
			}
			got := messages(d, "dns-dangling")
			for _, want := range []string{tt.message, "blog.example.com", strings.TrimSuffix(tt.target, ".")} {
				if !strings.Contains(got, want) {
					t.Errorf("got %q, want %q", got, want)
				}
			}
			if got := d.Grades[robertparker.AreaDNS]; got != tt.grade {
				t.Errorf("got grade %q, want %q, from %+v", got, tt.grade, d.Findings)
			}
		})
	}
}

func TestDanglingCNAMEsThatArentProblems(t *testing.T) {
	cname := func(target string) []dnsmessage.ResourceBody {
		return []dnsmessage.ResourceBody{&dnsmessage.CNAMEResource{CNAME: name(target)}}
	}
	tests := []struct {
		name   string
		answer []dnsmessage.ResourceBody
		rcode  dnsmessage.RCode
	}{
		{"a CNAME that resolves", append(cname("site.provider.example."), ipv4(192, 0, 2, 2)...), dnsmessage.RCodeSuccess},
		{"a target with no addresses", cname("site.provider.example."), dnsmessage.RCodeSuccess},
		{"a target that can't be looked up", cname("site.provider.example."), dnsmessage.RCodeServerFailure},
		{"a name that doesn't exist", nil, nameError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := danglingZone(nil)
			s.answers["blog.example.com. TypeA"] = tt.answer
			s.rcodes["blog.example.com. TypeA"] = tt.rcode
			d, err := checkDNS(t, s)
			if err != nil {
				t.Fatal(err)
			}
			if _, found := severities(d)["dns-dangling"]; found {
				t.Errorf("got %+v", d.Findings)
			}
		})
	}
}

// A wildcard can make every name lead to the same place, and that's one mistake, not dozens.
func TestDanglingCNAMEsWithOneTargetAreOneFinding(t *testing.T) {
	s := danglingZone(map[string]string{"blog": "gone.provider.example.", "shop": "gone.provider.example.", "www": "other.provider.example."})
	d, err := checkDNS(t, s)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, f := range d.Findings {
		if f.Check == "dns-dangling" {
			found = append(found, f.Message)
		}
	}
	if len(found) != 2 {
		t.Fatalf("got %q", found)
	}
	if !slices.ContainsFunc(found, func(m string) bool {
		return strings.Contains(m, "blog.example.com, shop.example.com points to gone.provider.example")
	}) {
		t.Errorf("got %q", found)
	}
}

func TestDanglingChecksTheNameGiven(t *testing.T) {
	s := danglingZone(map[string]string{"unusual": "gone.provider.example."})
	address := startDNS(t, s)
	d := robertparker.NewDomain("unusual.example.com")
	if err := robertparker.DNSAnalyzerRouted(address, nil, func(string) string { return address })(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if got := messages(d, "dns-dangling"); !strings.Contains(got, "unusual.example.com") {
		t.Errorf("got %+v", d.Findings)
	}
}

func TestDanglingFollowsChains(t *testing.T) {
	s := danglingZone(nil)
	s.answers["blog.example.com. TypeA"] = []dnsmessage.ResourceBody{
		&dnsmessage.CNAMEResource{CNAME: name("middle.example.com.")},
		&dnsmessage.CNAMEResource{CNAME: name("gone.azurewebsites.net.")},
	}
	s.rcodes["blog.example.com. TypeA"] = nameError
	d, err := checkDNS(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if got := severities(d)["dns-dangling"]; got != robertparker.SeverityFailure {
		t.Errorf("got %q, in %+v", got, d.Findings)
	}
}

// Only a domain that says it does not exist counts as unregistered.
func TestDanglingTargetDomainThatCantBeLookedUp(t *testing.T) {
	s := danglingZone(map[string]string{"blog": "www.long-gone.com."})
	s.rcodes["long-gone.com. TypeNS"] = dnsmessage.RCodeServerFailure
	d, err := checkDNS(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if got := severities(d)["dns-dangling"]; got != robertparker.SeverityWarning {
		t.Errorf("got %q, in %+v", got, d.Findings)
	}
}

func TestDanglingRunsOutOfTime(t *testing.T) {
	s := danglingZone(nil)
	s.hang = "www.example.com. TypeA"
	address := startDNS(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	d := robertparker.NewDomain("example.com")
	if err := robertparker.DNSAnalyzerRouted(address, nil, func(string) string { return address })(ctx, d); err == nil {
		t.Error("got no error")
	}
	if got := severities(d)["dns-dangling"]; got != robertparker.SeverityUnknown {
		t.Errorf("got %q, in %+v", got, d.Findings)
	}
}
