package robertparker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

//RDAP is the modern replacement for WHOIS. Each registry runs its own server, and IANA publishes which one to ask.

const (
	ianaBootstrap = "https://data.iana.org/rdap/dns.json"

	// rdapPerSecond and rdapConcurrency are the limits for each RDAP server. Registries publish no limits, and these
	// are well under what Verisign allowed when measured at 20 a second, to stay polite on long lists.
	rdapPerSecond   = 10
	rdapConcurrency = 4

	rdapTimeout    = 15 * time.Second
	rdapAttempts   = 3
	rdapMaxWait    = 30 * time.Second
	rdapMaxBody    = 1 << 20
	rdapMaxDNSBody = 8 << 20
)

// Registration is what a registry says about a domain.
type Registration struct {
	Registrar   string    //The registrar's name.
	RegistrarID string    //The registrar's IANA ID, which is sturdier than its name, if the registry gives one.
	Registered  time.Time //When the domain was registered.
}

// RegistrationSource looks up registrations. It returns nil if there's no data, because the domain isn't registered or
// its registry has no RDAP server, and an error if the lookup failed.
type RegistrationSource interface {
	Lookup(ctx context.Context, domain string) (*Registration, error)
}

// RDAP is a RegistrationSource that asks each registry's RDAP server, using IANA's list of them.
type RDAP struct {
	// These are for testing, and default to the real thing.
	Bootstrap string       //Where to get the list of servers.
	Client    *http.Client //How to reach them.

	mu       sync.Mutex
	servers  map[string]string   //Each TLD's server. Fetched on first use, and kept once that works.
	limiters map[string]*Limiter //Each server's limits.
}

// server returns the RDAP server for a domain's TLD, or "" if it doesn't have one.
func (r *RDAP) server(ctx context.Context, domain string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.servers == nil {
		if err := r.bootstrap(ctx); err != nil {
			return "", err
		}
	}
	return r.servers[domain[strings.LastIndex(domain, ".")+1:]], nil
}

// bootstrap fetches the list of servers. Its format is RFC 9224.
func (r *RDAP) bootstrap(ctx context.Context) error {
	source := r.Bootstrap
	if source == "" {
		source = ianaBootstrap
	}
	status, body, _, err := r.get(ctx, source, rdapMaxDNSBody)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("RDAP bootstrap: status %d", status)
	}
	var list struct {
		Services [][][]string `json:"services"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return fmt.Errorf("RDAP bootstrap: %w", err)
	}
	servers := map[string]string{}
	for _, service := range list.Services {
		if len(service) != 2 || len(service[1]) == 0 {
			continue
		}
		for _, tld := range service[0] {
			servers[strings.ToLower(tld)] = strings.TrimSuffix(service[1][0], "/")
		}
	}
	r.servers = servers
	return nil
}

// limiter returns the limits for a server.
func (r *RDAP) limiter(server string) *Limiter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.limiters == nil {
		r.limiters = map[string]*Limiter{}
	}
	if r.limiters[server] == nil {
		r.limiters[server] = NewLimiter(rdapConcurrency, rdapPerSecond)
	}
	return r.limiters[server]
}

// get fetches a URL, and returns its status, body, and headers.
func (r *RDAP) get(ctx context.Context, target string, limit int64) (int, []byte, http.Header, error) {
	ctx, cancel := context.WithTimeout(ctx, rdapTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/rdap+json, application/json")
	client := r.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	return resp.StatusCode, body, resp.Header, err
}

// Lookup returns the registration of a domain, which must be in punycode. It waits and tries again if a server says
// it's getting too many requests.
func (r *RDAP) Lookup(ctx context.Context, domain string) (*Registration, error) {
	server, err := r.server(ctx, domain)
	if err != nil || server == "" {
		return nil, err
	}
	limiter := r.limiter(server)
	target := server + "/domain/" + url.PathEscape(domain)
	for attempt := 1; ; attempt++ {
		var status int
		var body []byte
		var header http.Header
		err := limiter.Do(ctx, func(ctx context.Context) error {
			var err error
			status, body, header, err = r.get(ctx, target, rdapMaxBody)
			return err
		})
		switch {
		case err != nil:
			return nil, err
		case status == http.StatusOK:
			return parseRDAP(body)
		case status == http.StatusNotFound:
			return nil, nil
		case (status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable) && attempt < rdapAttempts:
			select {
			case <-time.After(rdapBackoff(header, attempt)):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		default:
			return nil, fmt.Errorf("RDAP lookup of %s: status %d", domain, status)
		}
	}
}

// rdapBackoff returns how long to wait before trying again, which is what the server asked for, if it said.
func rdapBackoff(header http.Header, attempt int) time.Duration {
	wait := time.Duration(attempt) * time.Second
	if seconds, err := strconv.Atoi(header.Get("Retry-After")); err == nil && seconds > 0 {
		wait = time.Duration(seconds) * time.Second
	}
	return min(wait, rdapMaxWait)
}

// parseRDAP reads the parts of an RDAP domain response (RFC 9083) that are compared.
func parseRDAP(body []byte) (*Registration, error) {
	var record struct {
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
		Entities []struct {
			Roles     []string          `json:"roles"`
			VCard     []json.RawMessage `json:"vcardArray"`
			PublicIDs []struct {
				Type       string `json:"type"`
				Identifier string `json:"identifier"`
			} `json:"publicIds"`
		} `json:"entities"`
	}
	if err := json.Unmarshal(body, &record); err != nil {
		return nil, fmt.Errorf("RDAP response: %w", err)
	}
	registration := &Registration{}
	for _, e := range record.Events {
		if e.Action != "registration" {
			continue
		}
		// A bad date only loses that detail. The rest of the record is still good.
		if t, err := time.Parse(time.RFC3339, e.Date); err == nil {
			registration.Registered = t
		}
	}
	for _, entity := range record.Entities {
		isRegistrar := false
		for _, role := range entity.Roles {
			isRegistrar = isRegistrar || role == "registrar"
		}
		if !isRegistrar {
			continue
		}
		for _, id := range entity.PublicIDs {
			if id.Type == "IANA Registrar ID" {
				registration.RegistrarID = id.Identifier
			}
		}
		if len(entity.VCard) == 2 {
			var properties [][]json.RawMessage
			if json.Unmarshal(entity.VCard[1], &properties) == nil {
				for _, p := range properties {
					var name, value string
					if len(p) == 4 && json.Unmarshal(p[0], &name) == nil && name == "fn" && json.Unmarshal(p[3], &value) == nil {
						registration.Registrar = value
					}
				}
			}
		}
	}
	return registration, nil
}
