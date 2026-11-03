package robertparker

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

//Concurrency for processing large numbers of domains, and for limiting calls to network services.

// Analyzer is one step of analysis on a domain, such as Entropy or Permute. Analyzers that make network calls should
// return promptly when ctx is done, and use a shared Limiter to cap calls to each service.
type Analyzer func(ctx context.Context, d *Domain) error

// EntropyAnalyzer is an Analyzer that runs Entropy.
func EntropyAnalyzer(_ context.Context, d *Domain) error {
	Entropy(d)
	return nil
}

// PermuteAnalyzer is an Analyzer that runs Permute.
func PermuteAnalyzer(_ context.Context, d *Domain) error {
	Permute(d)
	return nil
}

// Options configure Process.
type Options struct {
	Workers   int           //Domains analyzed at once. Defaults to runtime.GOMAXPROCS(0); raise it for network-bound analyzers.
	Analyzers []Analyzer    //Run in order on each domain. All run even if one fails.
	Timeout   time.Duration //If set, the time allowed for all analyzers on one domain.
	Unordered bool          //Send results as they finish, so one slow domain doesn't hold up the rest. Otherwise results are in input order.
}

// Result is a domain after analysis.
type Result struct {
	Input  string  //The domain as given.
	Domain *Domain //The domain, split by NewDomain and filled in by the analyzers.
	Err    error   //Errors from the analyzers, joined, or nil.
}

// Process runs NewDomain and opts.Analyzers on each domain from domains, using opts.Workers goroutines, and sends
// the results on the returned channel, which is closed once domains is closed and every result has been sent.
// Only a few domains per worker are in progress at once, so domains can be any length.
//
// If ctx is cancelled, Process stops reading domains, drops results not yet sent, and closes the channel once its
// workers have returned. Code sending on domains should also stop when ctx is done.
func Process(ctx context.Context, domains <-chan string, opts Options) <-chan Result {
	if opts.Workers <= 0 {
		opts.Workers = runtime.GOMAXPROCS(0)
	}
	out := make(chan Result, opts.Workers)
	if opts.Unordered {
		go processUnordered(ctx, domains, opts, out)
	} else {
		go processOrdered(ctx, domains, opts, out)
	}
	return out
}

// processUnordered has each worker read a domain, analyze it, and send the result.
func processUnordered(ctx context.Context, domains <-chan string, opts Options, out chan<- Result) {
	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				var s string
				var ok bool
				select {
				case s, ok = <-domains:
					if !ok {
						return
					}
				case <-ctx.Done():
					return
				}
				select {
				case out <- analyze(ctx, s, opts):
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	wg.Wait()
	close(out)
}

// processOrdered queues a result slot for each domain in input order, has the workers fill the slots, and sends
// them in queue order. The queue's buffer bounds how far workers can get ahead of a slow domain.
func processOrdered(ctx context.Context, domains <-chan string, opts Options, out chan<- Result) {
	type job struct {
		input  string
		result chan Result
	}
	jobs := make(chan job)
	queue := make(chan chan Result, opts.Workers)

	go func() {
		defer close(jobs)
		defer close(queue)
		for {
			var s string
			var ok bool
			select {
			case s, ok = <-domains:
				if !ok {
					return
				}
			case <-ctx.Done():
				return
			}
			j := job{s, make(chan Result, 1)}
			select {
			case queue <- j.result:
			case <-ctx.Done():
				return
			}
			select {
			case jobs <- j:
			case <-ctx.Done():
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				j.result <- analyze(ctx, j.input, opts)
			}
		}()
	}
	defer close(out)
	defer wg.Wait()

	for result := range queue {
		var r Result
		select {
		case r = <-result:
		case <-ctx.Done():
			return
		}
		select {
		case out <- r:
		case <-ctx.Done():
			return
		}
	}
}

// analyze splits one domain and runs every analyzer on it, joining their errors.
func analyze(ctx context.Context, s string, opts Options) Result {
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	r := Result{Input: s, Domain: NewDomain(s)}
	var errs []error
	for _, a := range opts.Analyzers {
		if err := a(ctx, r.Domain); err != nil {
			errs = append(errs, err)
		}
	}
	r.Err = errors.Join(errs...)
	return r
}

// Limiter caps the calls to one external service, such as a DNS resolver or an API, made at once and per second.
// Share one Limiter per service across all workers, so the cap holds however many workers there are.
// A nil *Limiter does not limit.
type Limiter struct {
	slots chan struct{}
	rate  *rate.Limiter
}

// NewLimiter returns a Limiter allowing at most concurrent calls at once and perSecond calls per second.
// Zero or less for either means no limit of that kind.
func NewLimiter(concurrent int, perSecond float64) *Limiter {
	l := &Limiter{}
	if concurrent > 0 {
		l.slots = make(chan struct{}, concurrent)
	}
	if perSecond > 0 {
		l.rate = rate.NewLimiter(rate.Limit(perSecond), 1)
	}
	return l
}

// Do waits for a free slot and the rate limit, then calls fn. It returns ctx.Err() without calling fn if ctx is
// done first.
func (l *Limiter) Do(ctx context.Context, fn func(context.Context) error) error {
	if l == nil {
		return fn(ctx)
	}
	if l.slots != nil {
		select {
		case l.slots <- struct{}{}:
			defer func() { <-l.slots }()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if l.rate != nil {
		if err := l.rate.Wait(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
	}
	return fn(ctx)
}
