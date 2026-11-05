package robertparker

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// BrandRanker rates brand matches on the same signs as RegistrationAnalyzer. It uses DNS and RDAP only, and never
// connects to a match. What it looks up is the registrable domain, since that's what has an owner.
type BrandRanker struct {
	lookup *lookalikeLookup
	source RegistrationSource
	now    func() time.Time

	mu     sync.Mutex
	brands map[string]*brandFacts //What's known about each brand. Failures aren't kept, so the next match tries again.
}

// brandFacts is what matches are compared with.
type brandFacts struct {
	nameServers  []string
	registration *Registration
}

// NewBrandRanker returns a ranker. Every DNS lookup goes through limiter, which can be nil, and now can be nil.
func NewBrandRanker(resolver LookalikeResolver, source RegistrationSource, limiter *Limiter, now func() time.Time) *BrandRanker {
	if now == nil {
		now = time.Now
	}
	return &BrandRanker{
		lookup: &lookalikeLookup{resolver: resolver, limiter: limiter, wildcards: map[string][]string{}},
		source: source,
		now:    now,
		brands: map[string]*brandFacts{},
	}
}

// facts returns what's known about a brand.
func (r *BrandRanker) facts(ctx context.Context, brand string) (*brandFacts, error) {
	r.mu.Lock()
	facts := r.brands[brand]
	r.mu.Unlock()
	if facts != nil {
		return facts, nil
	}
	// If this fails, matches just won't be marked as sharing name servers.
	servers, _ := r.lookup.nameServers(ctx, brand)
	registration, err := r.source.Lookup(ctx, brand)
	if err != nil {
		return nil, fmt.Errorf("registration lookup of %s: %w", brand, err)
	}
	facts = &brandFacts{servers, registration}
	r.mu.Lock()
	r.brands[brand] = facts
	r.mu.Unlock()
	return facts, nil
}

// Rank fills in what DNS and RDAP say about a match, and how suspicious it is. A name under a private suffix, like
// pages.dev, is SuspicionUnknown, since no registry knows about it. So is a match that an error stops.
func (r *BrandRanker) Rank(ctx context.Context, m *BrandMatch) error {
	m.Suspicion = SuspicionUnknown
	registrable := registrableUnderICANN(m.ASCII)
	if registrable == "" {
		return nil
	}
	facts, err := r.facts(ctx, m.Brand)
	if err != nil {
		return err
	}
	found, err := r.lookup.look(ctx, Permutation{Fuzzer: m.Fuzzer, Domain: registrable, ASCII: registrable}, facts.nameServers)
	if err != nil {
		return fmt.Errorf("lookup of %s: %w", registrable, err)
	}
	if found == nil {
		// Some suffixes, like .ph, answer for every name, and whoever runs that can get certificates for any name asked for,
		// so most of these were never registered by anyone.
		m.Suspicion = SuspicionLow
		m.Reasons = []string{"doesn't exist in DNS, apart from any wildcard on its suffix"}
		return nil
	}
	m.Addresses, m.NameServers, m.MailServers = found.Addresses, found.NameServers, found.MailServers
	m.SharedNameServers, m.BrokenDNS = found.SharedNameServers, found.BrokenDNS
	registration, err := r.source.Lookup(ctx, registrable)
	if err != nil {
		return fmt.Errorf("registration lookup of %s: %w", registrable, err)
	}
	m.judge(facts.registration, registration, r.now())
	return nil
}
