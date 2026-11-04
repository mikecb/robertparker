package robertparker_test

import (
	"context"
	"testing"

	"github.com/mikecb/robertparker"
)

func BenchmarkNewDomain(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		robertparker.NewDomain("www.example.com")
	}
}

func BenchmarkEntropy(b *testing.B) {
	d := robertparker.NewDomain("d1y6jrbzotnyjg.cloudfront.net")
	b.ReportAllocs()
	for b.Loop() {
		robertparker.Entropy(d)
	}
}

func BenchmarkPermute(b *testing.B) {
	d := robertparker.NewDomain("www.example.com")
	b.ReportAllocs()
	for b.Loop() {
		robertparker.Permute(d)
	}
}

func BenchmarkPermuteUnicode(b *testing.B) {
	d := robertparker.NewDomain("δοκιμή.δοκιμή")
	b.ReportAllocs()
	for b.Loop() {
		robertparker.Permute(d)
	}
}

func BenchmarkProcessPermute(b *testing.B) {
	in := numbered(1000)
	opts := robertparker.Options{Analyzers: []robertparker.Analyzer{robertparker.EntropyAnalyzer, robertparker.PermuteAnalyzer}}
	b.ReportAllocs()
	for b.Loop() {
		ctx := context.Background()
		for range robertparker.Process(ctx, feed(ctx, in), opts) {
		}
	}
}
