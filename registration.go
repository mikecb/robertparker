package robertparker

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/publicsuffix"
)

//Registration comparison ranks lookalikes. One registered through a different registrar than the original, recently,
//with mail servers, is much more likely to be malicious than one the original's owner registered defensively.

// Suspicion says how likely a lookalike is to be malicious. It's a way to sort them, and doesn't prove anything.
type Suspicion string

const (
	SuspicionHigh    Suspicion = "high"    //Several signs of a new, independent domain.
	SuspicionMedium  Suspicion = "medium"  //Some signs. Mostly parked domains that could be used for mail.
	SuspicionLow     Suspicion = "low"     //Few signs, or it looks like it belongs to the original's owner.
	SuspicionUnknown Suspicion = "unknown" //There's no registration data to compare, which says nothing either way.
)

// Each sign of a lookalike being malicious is worth points, so that no one thing decides. These are the numbers to
// change to make the ranking stricter or more lenient.
//
// A recent registration counts most, because phishing domains tend to be used soon after they're registered. Mail
// servers count less than they sound like they should, because parking services give their domains them too. A
// different registrar is a weak sign on its own, and the same registrar proves nothing, since brands often use the
// same big registrars as everyone else.
const (
	differentRegistrarPoints = 1
	recentPoints             = 2
	mailPoints               = 1

	highSuspicion   = 3
	mediumSuspicion = 2
)

// suspicionOrder sorts lookalikes, with what's worth looking at first.
var suspicionOrder = map[Suspicion]int{SuspicionHigh: 0, SuspicionMedium: 1, SuspicionUnknown: 2, SuspicionLow: 3}

const (
	// registrationConcurrency is how many lookalikes of one domain are looked up at once. RDAP limits each server.
	registrationConcurrency = 8

	// recentRegistration is how new a lookalike has to be to count as recent. Phishing domains tend to be used soon
	// after they're registered, while parked domains build up over years.
	recentRegistration = 365 * 24 * time.Hour
)

// RegistrationAnalyzer returns an Analyzer that looks up the registration of a domain and of each of its d.Lookalikes,
// compares them, and sorts d.Lookalikes with the most suspicious first. It goes after LookalikeAnalyzer. now is the
// current time, and can be nil.
//
// Lookalikes without registration data, because their registry has no RDAP server or they're under a private suffix,
// are SuspicionUnknown. Lookups that fail are counted in d.RegistrationFailures, and return an error.
func RegistrationAnalyzer(source RegistrationSource, now func() time.Time) Analyzer {
	if now == nil {
		now = time.Now
	}
	return func(ctx context.Context, d *Domain) error {
		if len(d.Lookalikes) == 0 {
			return nil
		}
		var canonical *Registration
		var canonicalErr error
		if registrableUnderICANN(d.registrable()) != "" {
			canonical, canonicalErr = source.Lookup(ctx, d.registrable())
		}
		if canonicalErr != nil {
			// Without the original there's nothing to compare, and every lookup would be wasted.
			d.RegistrationFailures = len(d.Lookalikes)
			for i := range d.Lookalikes {
				d.Lookalikes[i].Suspicion = SuspicionUnknown
			}
			return fmt.Errorf("registration lookup of %s: %w", d.registrable(), canonicalErr)
		}

		var failures atomic.Int64
		var firstErr error
		var once sync.Once
		var wg sync.WaitGroup
		slots := make(chan struct{}, registrationConcurrency)
		for i := range d.Lookalikes {
			l := &d.Lookalikes[i]
			name := registrableUnderICANN(l.ASCII)
			if name == "" {
				l.Suspicion = SuspicionUnknown
				continue
			}
			slots <- struct{}{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-slots }()
				registration, err := source.Lookup(ctx, name)
				if err != nil {
					failures.Add(1)
					once.Do(func() { firstErr = err })
				}
				l.judge(canonical, registration, now())
			}()
		}
		wg.Wait()

		slices.SortStableFunc(d.Lookalikes, func(a, b Lookalike) int {
			return suspicionOrder[a.Suspicion] - suspicionOrder[b.Suspicion]
		})
		d.RegistrationFailures = int(failures.Load())
		if d.RegistrationFailures > 0 {
			return fmt.Errorf("%d of %d registration lookups failed: %w", d.RegistrationFailures, len(d.Lookalikes), firstErr)
		}
		return nil
	}
}

// judge fills in what the registrations say about a lookalike. Either can be nil.
func (l *Lookalike) judge(canonical, registration *Registration, now time.Time) {
	if registration != nil {
		l.Registrar, l.Registered = registration.Registrar, registration.Registered
	}
	if l.SharedNameServers {
		l.Suspicion = SuspicionLow
		l.Reasons = append(l.Reasons, "shares name servers with the original")
		return
	}
	if canonical == nil || registration == nil || !canCompare(canonical, registration) {
		l.Suspicion = SuspicionUnknown
		return
	}

	points := 0
	if sameRegistrar(canonical, registration) {
		l.SameRegistrar = true
	} else {
		points += differentRegistrarPoints
		l.Reasons = append(l.Reasons, "has a different registrar from the original")
	}
	if !registration.Registered.IsZero() && now.Sub(registration.Registered) < recentRegistration {
		points += recentPoints
		l.Reasons = append(l.Reasons, "was registered in the last year")
	}
	if len(l.MailServers) > 0 {
		points += mailPoints
		l.Reasons = append(l.Reasons, "can receive mail")
	}
	switch {
	case points >= highSuspicion:
		l.Suspicion = SuspicionHigh
	case points >= mediumSuspicion:
		l.Suspicion = SuspicionMedium
	default:
		l.Suspicion = SuspicionLow
	}
}

// canCompare reports whether two registrations both say who the registrar is.
func canCompare(a, b *Registration) bool {
	return (a.RegistrarID != "" && b.RegistrarID != "") || (a.Registrar != "" && b.Registrar != "")
}

// sameRegistrar compares registrars by IANA ID if both have one, and otherwise by name.
func sameRegistrar(a, b *Registration) bool {
	if a.RegistrarID != "" && b.RegistrarID != "" {
		return a.RegistrarID == b.RegistrarID
	}
	return strings.EqualFold(a.Registrar, b.Registrar)
}

// registrableUnderICANN returns the domain a registry would know about, or "" if there isn't one. Names under private
// suffixes like appspot.com aren't in any registry.
func registrableUnderICANN(name string) string {
	if _, icann := publicsuffix.PublicSuffix(name); !icann {
		return ""
	}
	registrable, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return ""
	}
	return registrable
}
