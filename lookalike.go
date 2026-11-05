package robertparker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/publicsuffix"
)

//Lookalike lookup finds which permutations of a domain exist, using DNS only. It never connects to them: they may be
//malicious, and a request would tell their owner that someone is looking.

const (
	// lookalikeConcurrency is how many permutations of one domain are looked up at once.
	lookalikeConcurrency = 16

	// lookalikeTimeout is the time allowed for one DNS query. It starts after the limiter, because a domain can have
	// hundreds of queries, and time spent waiting behind a rate limit doesn't mean anything is wrong.
	lookalikeTimeout = 5 * time.Second

	// lookalikeRetries is how many more times a query that timed out or failed temporarily is tried.
	lookalikeRetries = 2
)

// Lookalike is a permutation of a domain that exists.
type Lookalike struct {
	Fuzzer            string   //The kind of permutation.
	Domain            string   //The lookalike, in Unicode.
	ASCII             string   //The lookalike, in punycode.
	Addresses         []string `json:",omitempty"` //Its IP addresses.
	NameServers       []string `json:",omitempty"` //Its name servers.
	MailServers       []string `json:",omitempty"` //Its mail servers. A lookalike that can receive mail is a strong sign of phishing.
	SharedNameServers bool     `json:",omitzero"`  //It uses the same exact name servers as the original, so it probably has the same owner.
	BrokenDNS         bool     `json:",omitzero"`  //It's registered, but its name servers don't answer properly, so there's nothing else to report about it.

	// These are set by RegistrationAnalyzer.
	Registrar     string    `json:",omitempty"` //Its registrar.
	Registered    time.Time `json:",omitzero"`  //When it was registered.
	SameRegistrar bool      `json:",omitzero"`  //It has the same registrar as the original.
	Suspicion     Suspicion `json:",omitempty"` //How likely it is to be malicious.
	Reasons       []string  `json:",omitempty"` //Why it got that rating.
}

// LookalikeResolver looks up the DNS records that show a domain exists. net.DefaultResolver is one, and tests use a fake.
type LookalikeResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// LookalikeAnalyzer returns an Analyzer that looks up a domain's permutations, and puts those that exist in
// d.Lookalikes, in the order of the permutations. It uses d.Permutations if PermuteAnalyzer has run, and otherwise
// generates them without storing them. Every lookup goes through limiter, which can be nil.
//
// A suffix that answers for every name, which some do, would make anything under it look registered. So each suffix is
// tested with a random name, and answers that match it don't count.
//
// Lookups that fail, as opposed to finding nothing, are counted in d.LookupFailures, and return an error, so that a
// short list can be told apart from a clean one.
func LookalikeAnalyzer(resolver LookalikeResolver, limiter *Limiter) Analyzer {
	shared := &lookalikeLookup{resolver: resolver, limiter: limiter, wildcards: map[string][]string{}}
	return func(ctx context.Context, d *Domain) error {
		name := d.registrable()
		if name == "" {
			return nil
		}
		permutations := d.Permutations
		if permutations == nil {
			permutations = Permute(d)
			d.Permutations = nil
		}

		// If this fails, lookalikes just won't be marked as sharing name servers.
		own, _ := shared.nameServers(ctx, name)

		found := make([]*Lookalike, len(permutations))
		var failures atomic.Int64
		var firstErr error
		var once sync.Once
		var wg sync.WaitGroup
		slots := make(chan struct{}, lookalikeConcurrency)
		for i, p := range permutations {
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				failures.Add(1)
				once.Do(func() { firstErr = ctx.Err() })
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-slots }()
				l, err := shared.look(ctx, p, own)
				if err != nil {
					failures.Add(1)
					once.Do(func() { firstErr = err })
					return
				}
				found[i] = l
			}()
		}
		wg.Wait()

		d.Lookalikes = nil
		for _, l := range found {
			if l != nil {
				d.Lookalikes = append(d.Lookalikes, *l)
			}
		}
		d.LookupFailures = int(failures.Load())
		if d.LookupFailures > 0 {
			return fmt.Errorf("%d of %d lookalike lookups failed: %w", d.LookupFailures, len(permutations), firstErr)
		}
		return nil
	}
}

// lookalikeLookup is what's shared across domains, which is what makes each suffix's wildcard test happen once.
type lookalikeLookup struct {
	resolver LookalikeResolver
	limiter  *Limiter

	mu        sync.Mutex
	wildcards map[string][]string //What each suffix answers for a random name.
}

// query runs one DNS query through the limiter, retrying if it fails in a way that may not last, since with this many
// queries some will be dropped. It returns false if nothing was found.
func (l *lookalikeLookup) query(ctx context.Context, fn func(context.Context) error) (bool, error) {
	for attempt := 0; ; attempt++ {
		err := l.limiter.Do(ctx, func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, lookalikeTimeout)
			defer cancel()
			return fn(ctx)
		})
		if isNotFound(err) {
			return false, nil
		}
		var dnsErr *net.DNSError
		retry := errors.As(err, &dnsErr) && (dnsErr.IsTimeout || dnsErr.IsTemporary)
		if !retry || attempt == lookalikeRetries || ctx.Err() != nil {
			return err == nil, err
		}
	}
}

// addresses returns the IP addresses of name, sorted, so that results don't depend on the order of the answer.
func (l *lookalikeLookup) addresses(ctx context.Context, name string) ([]string, error) {
	var addresses []string
	_, err := l.query(ctx, func(ctx context.Context) error {
		var err error
		addresses, err = l.resolver.LookupHost(ctx, name)
		return err
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(addresses)
	return addresses, nil
}

// nameServers returns the name servers of name, sorted.
func (l *lookalikeLookup) nameServers(ctx context.Context, name string) ([]string, error) {
	var servers []string
	_, err := l.query(ctx, func(ctx context.Context) error {
		servers = nil // This can run again after a failed attempt.
		records, err := l.resolver.LookupNS(ctx, name)
		for _, r := range records {
			servers = append(servers, strings.ToLower(strings.TrimSuffix(r.Host, ".")))
		}
		if len(servers) > 0 {
			return nil // Go returns the good records with an error if some were malformed.
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(servers)
	return servers, nil
}

// mailServers returns the mail servers of name, sorted, leaving out the null MX of a domain that takes no mail.
func (l *lookalikeLookup) mailServers(ctx context.Context, name string) ([]string, error) {
	var servers []string
	_, err := l.query(ctx, func(ctx context.Context) error {
		servers = nil // This can run again after a failed attempt.
		records, err := l.resolver.LookupMX(ctx, name)
		for _, r := range records {
			if host := strings.ToLower(strings.TrimSuffix(r.Host, ".")); host != "" {
				servers = append(servers, host)
			}
		}
		if len(servers) > 0 {
			return nil // Go returns the good records with an error if some were malformed.
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(servers)
	return servers, nil
}

// wildcard returns what suffix answers for a name nobody registered, or nothing if it doesn't. Failures aren't kept, so
// the next domain tries again.
func (l *lookalikeLookup) wildcard(ctx context.Context, suffix string) ([]string, error) {
	l.mu.Lock()
	answer, known := l.wildcards[suffix]
	l.mu.Unlock()
	if known {
		return answer, nil
	}
	answer, err := l.addresses(ctx, randomName(suffix))
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.wildcards[suffix] = answer
	l.mu.Unlock()
	return answer, nil
}

// randomName returns a name under suffix that nobody has registered.
func randomName(suffix string) string {
	random := make([]byte, 12)
	rand.Read(random)
	return "robertparker-" + hex.EncodeToString(random) + "." + suffix
}

// look finds out if a permutation exists, and returns nil if it doesn't.
func (l *lookalikeLookup) look(ctx context.Context, p Permutation, own []string) (*Lookalike, error) {
	addresses, hostErr := l.addresses(ctx, p.ASCII)
	if hostErr != nil && !isBrokenDNS(hostErr) {
		return nil, hostErr
	}
	servers, nsErr := l.nameServers(ctx, p.ASCII)
	if nsErr != nil && !isBrokenDNS(nsErr) {
		return nil, nsErr
	}
	suffix, _ := publicsuffix.PublicSuffix(p.ASCII)
	if len(addresses) == 0 && len(servers) == 0 {
		failure := errors.Join(hostErr, nsErr)
		if failure == nil {
			return nil, nil
		}
		// A name that doesn't exist gets NXDOMAIN. A server failure means it's delegated to servers that don't work, so
		// it's registered, unless it's the resolver that's failing, which would make every name look registered.
		if _, err := l.addresses(ctx, randomName(suffix)); err != nil {
			return nil, failure
		}
		return &Lookalike{Fuzzer: p.Fuzzer, Domain: p.Domain, ASCII: p.ASCII, BrokenDNS: true}, nil
	}

	wildcard, err := l.wildcard(ctx, suffix)
	if err != nil {
		return nil, err
	}
	addresses = slices.DeleteFunc(addresses, func(a string) bool { return slices.Contains(wildcard, a) })
	if len(addresses) == 0 && len(servers) == 0 {
		return nil, nil
	}

	mail, err := l.mailServers(ctx, p.ASCII)
	if err != nil && !isBrokenDNS(err) {
		return nil, err
	}
	found := &Lookalike{Fuzzer: p.Fuzzer, Domain: p.Domain, ASCII: p.ASCII, Addresses: addresses, NameServers: servers, MailServers: mail}
	// All of them have to match exactly. Being with the same provider means nothing, since Cloudflare and others host
	// millions of unrelated domains, but they hand out particular servers to each account.
	found.SharedNameServers = len(servers) > 0 && !slices.ContainsFunc(servers, func(s string) bool { return !slices.Contains(own, s) })
	return found, nil
}

// isBrokenDNS reports whether err means a domain's own DNS is broken: a SERVFAIL, in the words of Go's resolver or the
// Windows one, or records too malformed to use.
func isBrokenDNS(err error) bool {
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return false
	}
	for _, s := range []string{"server misbehaving", "server failure", "invalid names"} {
		if strings.Contains(dnsErr.Err, s) {
			return true
		}
	}
	return false
}

// isNotFound reports whether err means the record doesn't exist, as opposed to a lookup that failed.
func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
