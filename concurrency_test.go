package robertparker_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mikecb/robertparker"
)

// feed sends domains on a channel, stopping early if ctx is done, and closes it.
func feed(ctx context.Context, domains []string) <-chan string {
	ch := make(chan string)
	go func() {
		defer close(ch)
		for _, d := range domains {
			select {
			case ch <- d:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch
}

// numbered returns n distinct domains.
func numbered(n int) []string {
	domains := make([]string, n)
	for i := range domains {
		domains[i] = fmt.Sprintf("d%d.example.com", i)
	}
	return domains
}

// jitter is an Analyzer that sleeps for a random few milliseconds, so workers finish out of order.
func jitter(ctx context.Context, d *robertparker.Domain) error {
	select {
	case <-time.After(time.Duration(rand.Intn(3000)) * time.Microsecond):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func collect(results <-chan robertparker.Result) []robertparker.Result {
	var all []robertparker.Result
	for r := range results {
		all = append(all, r)
	}
	return all
}

func ExampleProcess() {
	ctx := context.Background()
	domains := make(chan string)
	go func() {
		defer close(domains)
		for _, d := range []string{"www.google.com", "foo.appspot.com", "test.google"} {
			domains <- d
		}
	}()

	opts := robertparker.Options{Analyzers: []robertparker.Analyzer{robertparker.EntropyAnalyzer}}
	for r := range robertparker.Process(ctx, domains, opts) {
		fmt.Printf("%s %.3f %v\n", r.Domain.FQDN, r.Domain.Entropy, r.Err)
	}
	//Output:
	// google.com 1.918 <nil>
	// foo.appspot.com 0.918 <nil>
	// test.google 1.500 <nil>
}

func TestProcessMatchesSequential(t *testing.T) {
	ctx := context.Background()
	opts := robertparker.Options{Workers: 8, Analyzers: []robertparker.Analyzer{robertparker.EntropyAnalyzer, robertparker.PermuteAnalyzer}}
	results := collect(robertparker.Process(ctx, feed(ctx, domains), opts))
	if len(results) != len(domains) {
		t.Fatalf("got %d results for %d domains", len(results), len(domains))
	}
	for i, r := range results {
		want := robertparker.NewDomain(domains[i])
		robertparker.Entropy(want)
		robertparker.Permute(want)
		if r.Input != domains[i] || r.Err != nil || !reflect.DeepEqual(r.Domain, want) {
			t.Errorf("result %d for %s differs from sequential analysis", i, domains[i])
		}
	}
}

func TestProcessOrdered(t *testing.T) {
	ctx := context.Background()
	in := numbered(500)
	opts := robertparker.Options{Workers: 16, Analyzers: []robertparker.Analyzer{jitter}}
	results := collect(robertparker.Process(ctx, feed(ctx, in), opts))
	if len(results) != len(in) {
		t.Fatalf("got %d results for %d domains", len(results), len(in))
	}
	for i, r := range results {
		if r.Input != in[i] {
			t.Fatalf("result %d is %s, want %s", i, r.Input, in[i])
		}
	}
}

func TestProcessUnordered(t *testing.T) {
	ctx := context.Background()
	in := numbered(500)
	opts := robertparker.Options{Workers: 16, Unordered: true, Analyzers: []robertparker.Analyzer{jitter}}
	var got []string
	for r := range robertparker.Process(ctx, feed(ctx, in), opts) {
		got = append(got, r.Input)
	}
	sort.Strings(got)
	want := append([]string{}, in...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("unordered results are not the same set as the input: got %d, want %d", len(got), len(want))
	}
}

func TestProcessWorkerLimit(t *testing.T) {
	for _, unordered := range []bool{false, true} {
		var running, peak int64
		count := func(ctx context.Context, d *robertparker.Domain) error {
			n := atomic.AddInt64(&running, 1)
			for {
				p := atomic.LoadInt64(&peak)
				if n <= p || atomic.CompareAndSwapInt64(&peak, p, n) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			atomic.AddInt64(&running, -1)
			return nil
		}
		ctx := context.Background()
		opts := robertparker.Options{Workers: 5, Unordered: unordered, Analyzers: []robertparker.Analyzer{count}}
		collect(robertparker.Process(ctx, feed(ctx, numbered(100)), opts))
		if peak != 5 {
			t.Errorf("unordered=%v: peak of %d analyzers at once, want 5", unordered, peak)
		}
	}
}

func TestProcessErrors(t *testing.T) {
	errA, errB := errors.New("a failed"), errors.New("b failed")
	var ranAfter int64
	failA := func(_ context.Context, d *robertparker.Domain) error {
		if d.Secondary == "bad" {
			return errA
		}
		return nil
	}
	failB := func(_ context.Context, d *robertparker.Domain) error {
		atomic.AddInt64(&ranAfter, 1)
		if d.Secondary == "bad" {
			return errB
		}
		return nil
	}
	ctx := context.Background()
	opts := robertparker.Options{Analyzers: []robertparker.Analyzer{failA, failB, robertparker.EntropyAnalyzer}}
	results := collect(robertparker.Process(ctx, feed(ctx, []string{"good.com", "bad.com", "fine.com"}), opts))
	if len(results) != 3 || results[0].Err != nil || results[2].Err != nil {
		t.Fatalf("want errors only for bad.com, got %+v", results)
	}
	if !errors.Is(results[1].Err, errA) || !errors.Is(results[1].Err, errB) {
		t.Errorf("want both errors joined, got %v", results[1].Err)
	}
	if ranAfter != 3 || results[1].Domain.Entropy == 0 {
		t.Error("analyzers after a failure did not run")
	}
}

func TestProcessEncode(t *testing.T) {
	for _, unordered := range []bool{false, true} {
		var running, peak int64
		encode := func(d *robertparker.Domain) ([]byte, error) {
			n := atomic.AddInt64(&running, 1)
			for {
				p := atomic.LoadInt64(&peak)
				if n <= p || atomic.CompareAndSwapInt64(&peak, p, n) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			atomic.AddInt64(&running, -1)
			return []byte(d.Secondary), nil
		}
		ctx := context.Background()
		opts := robertparker.Options{Workers: 4, Unordered: unordered, Encode: encode}
		for r := range robertparker.Process(ctx, feed(ctx, numbered(40)), opts) {
			if string(r.Encoded) != r.Domain.Secondary || r.Err != nil {
				t.Fatalf("unordered=%v: got Encoded %q, Err %v for %s", unordered, r.Encoded, r.Err, r.Input)
			}
		}
		if peak != 4 {
			t.Errorf("unordered=%v: peak of %d encoders at once, want 4 running on the workers", unordered, peak)
		}
	}
}

func TestProcessEncodeSeesAnalyzers(t *testing.T) {
	ctx := context.Background()
	opts := robertparker.Options{
		Analyzers: []robertparker.Analyzer{robertparker.EntropyAnalyzer},
		Encode: func(d *robertparker.Domain) ([]byte, error) {
			return []byte(fmt.Sprintf("%.3f", d.Entropy)), nil
		},
	}
	results := collect(robertparker.Process(ctx, feed(ctx, []string{"google.com"}), opts))
	if len(results) != 1 || string(results[0].Encoded) != "1.918" {
		t.Errorf("Encode did not run after the analyzers: %+v", results)
	}
}

func TestProcessEncodeError(t *testing.T) {
	errAnalyze, errEncode := errors.New("analyzer failed"), errors.New("encode failed")
	ctx := context.Background()
	opts := robertparker.Options{
		Analyzers: []robertparker.Analyzer{func(context.Context, *robertparker.Domain) error { return errAnalyze }},
		Encode:    func(*robertparker.Domain) ([]byte, error) { return nil, errEncode },
	}
	results := collect(robertparker.Process(ctx, feed(ctx, []string{"google.com"}), opts))
	if len(results) != 1 || !errors.Is(results[0].Err, errAnalyze) || !errors.Is(results[0].Err, errEncode) {
		t.Errorf("want both errors joined, got %+v", results)
	}
}

func TestProcessTimeout(t *testing.T) {
	block := func(ctx context.Context, d *robertparker.Domain) error {
		if d.Secondary == "slow" {
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}
	ctx := context.Background()
	opts := robertparker.Options{Timeout: 20 * time.Millisecond, Analyzers: []robertparker.Analyzer{block}}
	start := time.Now()
	results := collect(robertparker.Process(ctx, feed(ctx, []string{"slow.com", "fast.com"}), opts))
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v with a 20ms timeout", elapsed)
	}
	if len(results) != 2 || !errors.Is(results[0].Err, context.DeadlineExceeded) || results[1].Err != nil {
		t.Errorf("want a deadline error for slow.com only, got %+v", results)
	}
}

func TestProcessCancel(t *testing.T) {
	for _, unordered := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		endless := make(chan string)
		go func() {
			defer close(endless)
			for i := 0; ; i++ {
				select {
				case endless <- fmt.Sprintf("d%d.example.com", i):
				case <-ctx.Done():
					return
				}
			}
		}()
		opts := robertparker.Options{Workers: 4, Unordered: unordered, Analyzers: []robertparker.Analyzer{jitter}}
		results := robertparker.Process(ctx, endless, opts)
		for i := 0; i < 20; i++ {
			<-results
		}
		cancel()
		done := make(chan struct{})
		go func() {
			for range results {
			}
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("unordered=%v: results channel not closed after cancel", unordered)
		}
	}
}

func TestProcessStreams(t *testing.T) {
	// Results arrive before the input ends, so Process does not read all of it first.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := make(chan string)
	results := robertparker.Process(ctx, in, robertparker.Options{Workers: 2})
	for i := 0; i < 10; i++ {
		select {
		case in <- fmt.Sprintf("d%d.example.com", i):
		case <-time.After(2 * time.Second):
			t.Fatalf("Process stopped reading input after %d domains while no results were read", i)
		}
		if r := <-results; r.Input != fmt.Sprintf("d%d.example.com", i) {
			t.Fatalf("got %s for input %d", r.Input, i)
		}
	}
	close(in)
	if _, ok := <-results; ok {
		t.Error("results channel not closed after input closed")
	}
}

func TestLimiterConcurrency(t *testing.T) {
	l := robertparker.NewLimiter(3, 0)
	var running, peak int64
	ctx := context.Background()
	opts := robertparker.Options{Workers: 20, Unordered: true, Analyzers: []robertparker.Analyzer{
		func(ctx context.Context, d *robertparker.Domain) error {
			return l.Do(ctx, func(context.Context) error {
				n := atomic.AddInt64(&running, 1)
				for {
					p := atomic.LoadInt64(&peak)
					if n <= p || atomic.CompareAndSwapInt64(&peak, p, n) {
						break
					}
				}
				time.Sleep(2 * time.Millisecond)
				atomic.AddInt64(&running, -1)
				return nil
			})
		},
	}}
	for r := range robertparker.Process(ctx, feed(ctx, numbered(60)), opts) {
		if r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	if peak != 3 {
		t.Errorf("peak of %d calls at once across 20 workers, want 3", peak)
	}
}

func TestLimiterRate(t *testing.T) {
	l := robertparker.NewLimiter(0, 100)
	start := time.Now()
	for i := 0; i < 11; i++ {
		if err := l.Do(context.Background(), func(context.Context) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	// The first call is immediate, then one every 10ms.
	if elapsed := time.Since(start); elapsed < 90*time.Millisecond {
		t.Errorf("11 calls at 100 per second took %v, want at least 100ms", elapsed)
	}
}

func TestLimiterCancel(t *testing.T) {
	l := robertparker.NewLimiter(1, 0)
	held, hold := make(chan struct{}), make(chan struct{})
	go l.Do(context.Background(), func(context.Context) error { close(held); <-hold; return nil })
	defer close(hold)
	<-held

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	called := false
	err := l.Do(ctx, func(context.Context) error { called = true; return nil })
	if !errors.Is(err, context.DeadlineExceeded) || called {
		t.Errorf("want DeadlineExceeded without calling fn while the only slot is held, got %v, called=%v", err, called)
	}
}

func TestLimiterNil(t *testing.T) {
	var l *robertparker.Limiter
	want := errors.New("passed through")
	if err := l.Do(context.Background(), func(context.Context) error { return want }); err != want {
		t.Errorf("nil Limiter: got %v, want fn's error", err)
	}
}
