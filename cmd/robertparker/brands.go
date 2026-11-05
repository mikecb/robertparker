package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mikecb/robertparker"
)

const brandHeader = "SEEN\tBRAND\tKIND\tSUSPICION\tNAME\tASCII\tSOURCE\tREASONS"

// hunt is what -watch and -match need.
type hunt struct {
	match, owned, format, dnsServer string
	rank, suspicious                bool
	rate                            float64
	workers                         int
	stdin                           io.Reader
	stdout, stderr                  io.Writer
}

// collect gathers everything from readDomains.
func collect(domains <-chan string, readErr <-chan error) ([]string, error) {
	var all []string
	for d := range domains {
		all = append(all, d)
	}
	return all, <-readErr
}

// readBrands returns the brands, and the domains they also own.
func (h *hunt) readBrands(ctx context.Context, domains <-chan string, readErr <-chan error) ([]string, []string, error) {
	brands, err := collect(domains, readErr)
	if err != nil || h.owned == "" {
		return brands, nil, err
	}
	f, err := os.Open(h.owned)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	owned, err := collect(readDomains(ctx, nil, f))
	return brands, owned, err
}

// source returns where names come from.
func (h *hunt) source(client *http.Client) (robertparker.NameSource, func(), error) {
	switch h.match {
	case "":
		reader := certificates
		if client != nil {
			reader.Client = client
		}
		reader.Started = func(log robertparker.CTLog) { fmt.Fprintf(h.stderr, "robertparker: following %s\n", log.Name) }
		reader.Report = func(log string, err error) { fmt.Fprintf(h.stderr, "robertparker: %s: %v\n", log, err) }
		return reader.Names, func() {}, nil
	case "-":
		return robertparker.NamesFrom(h.stdin), func() {}, nil
	}
	f, err := os.Open(h.match)
	if err != nil {
		return nil, nil, err
	}
	return robertparker.NamesFrom(f), func() { f.Close() }, nil
}

// run reports matches as they're found. Each one is written straight away, since a watch can run for days.
func (h *hunt) run(ctx context.Context, domains <-chan string, readErr <-chan error) int {
	brands, owned, err := h.readBrands(ctx, domains, readErr)
	if err != nil {
		fmt.Fprintf(h.stderr, "robertparker: %v\n", err)
		return 1
	}
	matcher := robertparker.NewBrandMatcher(brands, owned)

	names, registry := lookalikes, registrations
	var client *http.Client
	if h.dnsServer != "" {
		custom := newResolver(h.dnsServer)
		names = custom
		client = &http.Client{Transport: &http.Transport{DialContext: (&net.Dialer{Resolver: custom}).DialContext}}
		if _, real := registry.(*robertparker.RDAP); real {
			registry = &robertparker.RDAP{Client: client}
		}
	}
	source, done, err := h.source(client)
	if err != nil {
		fmt.Fprintf(h.stderr, "robertparker: %v\n", err)
		return 1
	}
	defer done()
	var rank func(context.Context, *robertparker.BrandMatch) error
	if h.rank {
		limiter := robertparker.NewLimiter(limiterConcurrency, h.rate)
		rank = robertparker.NewBrandRanker(names, registry, limiter, nil).Rank
	}

	w := bufio.NewWriter(h.stdout)
	defer w.Flush()
	enc := json.NewEncoder(w)
	switch h.format {
	case "pretty":
		enc.SetIndent("", "  ")
	case "text":
		fmt.Fprintln(w, brandHeader)
		w.Flush()
	}

	code := 0
	for r := range matcher.Find(ctx, source, rank, h.workers) {
		if r.Err != nil {
			fmt.Fprintf(h.stderr, "robertparker: %v\n", r.Err)
			code = 1
		}
		m := r.Match
		if m.ASCII == "" || h.suspicious && m.Suspicion != robertparker.SuspicionHigh && m.Suspicion != robertparker.SuspicionMedium {
			continue
		}
		if h.format == "text" {
			writeBrandMatch(w, &m)
		} else if err := enc.Encode(&m); err != nil {
			fmt.Fprintf(h.stderr, "robertparker: %v\n", err)
			return 1
		}
		if err := w.Flush(); err != nil {
			fmt.Fprintf(h.stderr, "robertparker: %v\n", err)
			return 1
		}
	}
	if ctx.Err() != nil && h.match != "" {
		fmt.Fprintln(h.stderr, "robertparker: interrupted")
		return 130
	}
	return code
}

// writeBrandMatch writes a match as a row of tab-separated columns. They aren't aligned, since that would mean waiting.
func writeBrandMatch(w io.Writer, m *robertparker.BrandMatch) {
	seen := ""
	if !m.Seen.IsZero() {
		seen = m.Seen.Format(time.DateTime)
	}
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", orDash(seen), m.Brand, m.Fuzzer, orDash(string(m.Suspicion)), m.Domain, m.ASCII, orDash(m.Source), orDash(strings.Join(m.Reasons, ", ")))
}
