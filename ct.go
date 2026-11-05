package robertparker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

//Certificate Transparency logs record nearly every certificate issued, which makes them a feed of new names as they
//appear. This reads the static-ct-api logs that also publish names tiles (https://c2sp.org/static-ct-api), which hold just
//the names from a tile of certificates, at under 5% of the size. Logs that don't publish them are left out, since their
//full tiles would cost over 20 times the bandwidth, and 97% of a sample of certificates from them were in the others too.
//
//Nothing here verifies a log's signatures or proofs. That's for checking that logs are honest, and this only wants names.

const (
	ctLogList = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

	// ctTileWidth is how many entries a full tile holds.
	ctTileWidth = 256

	// ctPollInterval is how often to look for new entries. The busiest logs fill a tile about every second.
	ctPollInterval = 10 * time.Second

	// ctPartialWait is how long to wait for a tile to fill before reading the part that's there. The spec asks clients to
	// read full tiles when they can, and quiet logs take minutes to fill one.
	ctPartialWait = 10 * time.Minute

	// ctListRefresh is how often to look for new logs. A new log starts each half year.
	ctListRefresh = 24 * time.Hour

	// ctLongestCertificate is the longest a new certificate can last. Each log takes certificates that expire in its
	// interval, so this is how far ahead of today a log can start and still get new ones.
	ctLongestCertificate = 200 * 24 * time.Hour

	ctTimeout = 30 * time.Second
	ctMaxBody = 32 << 20
)

// CTLog is a Certificate Transparency log.
type CTLog struct {
	Name string //Its name, like "Let's Encrypt Sycamore2027h1".
	URL  string //Where it serves its entries, without a trailing slash.
}

// Sighting is a name that was seen somewhere.
type Sighting struct {
	Name   string    //The name.
	Seen   time.Time //When, if it's known.
	Source string    //Where, if it's known.
}

// CTReader follows Certificate Transparency logs.
type CTReader struct {
	Report  func(log string, err error) //Told about problems that it works around. It can be nil.
	Started func(log CTLog)             //Told about each log it starts following. It can be nil.

	// These are for testing, and default to the real thing.
	List   string           //Where to get the list of logs.
	Client *http.Client     //How to reach them.
	Poll   time.Duration    //How often to look for new entries.
	Wait   time.Duration    //How long to wait for a tile to fill.
	Now    func() time.Time //The current time.
}

// report passes on a problem.
func (r *CTReader) report(log string, err error) {
	if r.Report != nil {
		r.Report(log, err)
	}
}

// now returns the current time.
func (r *CTReader) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// ctNotFound is what fetching a missing file returns.
var ctNotFound = errors.New("not found")

// ctBusy is what fetching returns when a server says to wait.
type ctBusy struct {
	status int
	header http.Header
}

func (e *ctBusy) Error() string { return fmt.Sprintf("status %d", e.status) }

// get fetches a URL. Go's HTTP client asks for gzip and undoes it, which is what the logs expect.
func (r *CTReader) get(ctx context.Context, target string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, ctTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	client := r.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ctNotFound
	case resp.StatusCode != http.StatusOK:
		return nil, &ctBusy{resp.StatusCode, resp.Header}
	}
	return io.ReadAll(io.LimitReader(resp.Body, ctMaxBody))
}

// keepTrying fetches a URL until it works or ctx is done. A log that's down for a while mustn't lose entries.
func (r *CTReader) keepTrying(ctx context.Context, log CTLog, target string) ([]byte, error) {
	for attempt := 1; ; attempt++ {
		body, err := r.get(ctx, target)
		if err == nil {
			return body, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		r.report(log.Name, fmt.Errorf("%s: %w", target, err))
		var header http.Header
		var busy *ctBusy
		if errors.As(err, &busy) {
			header = busy.header
		}
		select {
		case <-time.After(rdapBackoff(header, attempt)):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// checkpointSize returns how many entries a checkpoint says a log has.
func checkpointSize(body []byte) (int64, error) {
	lines := strings.SplitN(string(body), "\n", 3)
	if len(lines) < 3 {
		return 0, errors.New("malformed checkpoint")
	}
	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || size < 0 {
		return 0, errors.New("malformed checkpoint")
	}
	return size, nil
}

// tilePath returns the path of tile n, which has each three digits in a directory of its own: x001/x234/067.
func tilePath(n int64) string {
	path := fmt.Sprintf("%03d", n%1000)
	for n /= 1000; n > 0; n /= 1000 {
		path = fmt.Sprintf("x%03d/%s", n%1000, path)
	}
	return path
}

// tileURL returns where tile n of a log is, or the first width entries of it, if width isn't 0.
func tileURL(log CTLog, n int64, width int64) string {
	target := log.URL + "/tile/names/" + tilePath(n)
	if width > 0 {
		target += fmt.Sprintf(".p/%d", width)
	}
	return target
}

// parseNamesTile returns the sightings in a names tile, one for each entry, in order. An entry that can't be read keeps
// its place, so the entries after it are still counted properly.
func parseNamesTile(body []byte, log CTLog) ([][]Sighting, int) {
	var entries [][]Sighting
	bad := 0
	for line := range bytes.Lines(body) {
		var entry struct {
			Timestamp int64
			DNS       []string
		}
		if err := json.Unmarshal(line, &entry); err != nil {
			bad++
		}
		seen := time.UnixMilli(entry.Timestamp).UTC()
		sightings := make([]Sighting, 0, len(entry.DNS))
		for _, name := range entry.DNS {
			sightings = append(sightings, Sighting{Name: name, Seen: seen, Source: log.Name})
		}
		entries = append(entries, sightings)
	}
	return entries, bad
}

// tail follows a log from its current end until ctx is done, reading one tile at a time, so that each log has one
// request running at most. A log that falls behind catches up the same way.
func (r *CTReader) tail(ctx context.Context, log CTLog, emit func(Sighting)) error {
	poll, wait := r.Poll, r.Wait
	if poll == 0 {
		poll = ctPollInterval
	}
	if wait == 0 {
		wait = ctPartialWait
	}
	size, err := r.size(ctx, log)
	if err != nil {
		return err
	}
	next, waiting := size, r.now()
	read := func(tile, width int64, body []byte) {
		entries, bad := parseNamesTile(body, log)
		if bad > 0 {
			r.report(log.Name, fmt.Errorf("%d unreadable entries in tile %d", bad, tile))
		}
		for _, entry := range entries[min(next%ctTileWidth, int64(len(entries))):] {
			for _, s := range entry {
				emit(s)
			}
		}
		if width == 0 {
			width = ctTileWidth
		}
		next, waiting = tile*ctTileWidth+width, r.now()
	}
	for {
		for next/ctTileWidth < size/ctTileWidth {
			tile := next / ctTileWidth
			body, err := r.keepTrying(ctx, log, tileURL(log, tile, 0))
			if err != nil {
				return err
			}
			read(tile, 0, body)
		}
		if size > next && r.now().Sub(waiting) >= wait {
			// This only gets one try. A log can drop a partial tile once the full one is out, which is what's next anyway.
			if body, err := r.get(ctx, tileURL(log, size/ctTileWidth, size%ctTileWidth)); err == nil {
				read(size/ctTileWidth, size%ctTileWidth, body)
			} else {
				waiting = r.now()
			}
		}
		select {
		case <-time.After(poll):
		case <-ctx.Done():
			return ctx.Err()
		}
		if size, err = r.size(ctx, log); err != nil {
			return err
		}
	}
}

// size returns how many entries a log has, trying until it works.
func (r *CTReader) size(ctx context.Context, log CTLog) (int64, error) {
	for {
		body, err := r.keepTrying(ctx, log, log.URL+"/checkpoint")
		if err != nil {
			return 0, err
		}
		size, err := checkpointSize(body)
		if err == nil {
			return size, nil
		}
		r.report(log.Name, err)
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}

// ctLogFile is the part of a log list that's used. Its format is Chrome's, version 3.
type ctLogFile struct {
	Operators []struct {
		TiledLogs []struct {
			Description string                     `json:"description"`
			URL         string                     `json:"monitoring_url"`
			State       map[string]json.RawMessage `json:"state"`
			Interval    *struct {
				Start time.Time `json:"start_inclusive"`
				End   time.Time `json:"end_exclusive"`
			} `json:"temporal_interval"`
		} `json:"tiled_logs"`
	} `json:"operators"`
}

// Logs returns the logs that a new certificate can be in, and that publish names tiles.
func (r *CTReader) Logs(ctx context.Context) ([]CTLog, error) {
	target := r.List
	if target == "" {
		target = ctLogList
	}
	body, err := r.get(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("log list: %w", err)
	}
	var list ctLogFile
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("log list: %w", err)
	}
	now := r.now()
	var candidates []CTLog
	for _, operator := range list.Operators {
		for _, l := range operator.TiledLogs {
			_, usable := l.State["usable"]
			_, qualified := l.State["qualified"]
			if !usable && !qualified || l.Interval == nil {
				continue
			}
			if l.Interval.End.After(now) && l.Interval.Start.Before(now.Add(ctLongestCertificate)) {
				candidates = append(candidates, CTLog{Name: l.Description, URL: strings.TrimSuffix(l.URL, "/")})
			}
		}
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	ok := make([]bool, len(candidates))
	for i, log := range candidates {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := r.probe(ctx, log)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				ok[i] = true
			} else if !errors.Is(err, ctNotFound) {
				r.report(log.Name, err)
			}
		}()
	}
	wg.Wait()
	var logs []CTLog
	for i, log := range candidates {
		if ok[i] {
			logs = append(logs, log)
		}
	}
	return logs, nil
}

// probe checks that a log publishes names tiles, by fetching the last full one.
func (r *CTReader) probe(ctx context.Context, log CTLog) error {
	body, err := r.get(ctx, log.URL+"/checkpoint")
	if err != nil {
		return err
	}
	size, err := checkpointSize(body)
	if err != nil {
		return err
	}
	if size < ctTileWidth {
		return ctNotFound // There's nothing to tell by yet. The next look at the list will see.
	}
	_, err = r.get(ctx, tileURL(log, size/ctTileWidth-1, 0))
	return err
}

// Names sends the names on new certificates to emit, from every log, until ctx is done. It calls emit from many
// goroutines. It only returns an error of its own if there's nothing to read.
func (r *CTReader) Names(ctx context.Context, emit func(Sighting)) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	following := map[string]bool{}
	for {
		logs, err := r.Logs(ctx)
		if err != nil && len(following) == 0 {
			return err
		}
		if err != nil {
			r.report("", err)
		}
		for _, log := range logs {
			if !following[log.URL] {
				following[log.URL] = true
				if r.Started != nil {
					r.Started(log)
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					r.tail(ctx, log, emit)
				}()
			}
		}
		if len(following) == 0 {
			return errors.New("no certificate logs publish names tiles")
		}
		select {
		case <-time.After(ctListRefresh):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
