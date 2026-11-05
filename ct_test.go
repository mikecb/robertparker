package robertparker_test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mikecb/robertparker"
)

// fakeLog is a certificate log, with a list of logs at /list.json.
type fakeLog struct {
	t      *testing.T
	server *httptest.Server

	mu       sync.Mutex
	names    []string          //One name for each entry.
	missing  map[string]int    //How many more times to answer 503 for a path.
	gone     map[string]bool   //Paths to answer 404 for.
	hits     map[string]int    //How many times each path was asked for.
	agents   map[string]bool   //The User-Agents seen.
	body     map[string]string //Replacement bodies for paths.
	noTiles  bool              //There are no names tiles.
	interval [2]time.Time      //What the list says the log covers.
	state    string            //What the list says about the log.
}

func newFakeLog(t *testing.T, entries int) *fakeLog {
	t.Helper()
	l := &fakeLog{
		t: t, missing: map[string]int{}, gone: map[string]bool{}, hits: map[string]int{}, agents: map[string]bool{}, body: map[string]string{},
		interval: [2]time.Time{time.Now().Add(-time.Hour), time.Now().Add(time.Hour)}, state: "usable",
	}
	for i := range entries {
		l.names = append(l.names, fmt.Sprintf("n%d.example", i))
	}
	l.server = httptest.NewServer(http.HandlerFunc(l.serve))
	t.Cleanup(l.server.Close)
	return l
}

// add puts more entries on the end of the log.
func (l *fakeLog) add(names ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.names = append(l.names, names...)
}

// awaitTail waits for a reader to find where the log ends, since it only sends what comes after that. It asks for the
// checkpoint once to see if the log is worth reading, and again when it starts following it.
func (l *fakeLog) awaitTail(ctx context.Context) {
	for ctx.Err() == nil {
		reads := 0
		l.locked(func() { reads = l.hits["/checkpoint"] })
		if reads >= 2 {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// locked runs fn with the log to itself, which anything touching its fields needs, since the server runs on its own.
func (l *fakeLog) locked(fn func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fn()
}

func (l *fakeLog) serve(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	path := r.URL.Path
	l.hits[path]++
	l.agents[r.UserAgent()] = true
	if l.missing[path] > 0 {
		l.missing[path]--
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if l.gone[path] {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if body, ok := l.body[path]; ok {
		fmt.Fprint(w, body)
		return
	}
	switch {
	case path == "/list.json":
		fmt.Fprintf(w, `{"operators": [{"tiled_logs": [{"description": "Test log", "monitoring_url": %q, "state": {%q: {}}, "temporal_interval": {"start_inclusive": %q, "end_exclusive": %q}}]}]}`,
			l.server.URL+"/", l.state, l.interval[0].Format(time.RFC3339), l.interval[1].Format(time.RFC3339))
	case path == "/checkpoint":
		fmt.Fprintf(w, "test.example/log\n%d\nAAAA\n\n— test.example/log AAAA\n", len(l.names))
	case strings.HasPrefix(path, "/tile/names/") && !l.noTiles:
		l.serveTile(w, strings.TrimPrefix(path, "/tile/names/"))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// serveTile serves a names tile, gzipped like the real ones.
func (l *fakeLog) serveTile(w http.ResponseWriter, path string) {
	path, partial, isPartial := strings.Cut(path, ".p/")
	n, err := strconv.Atoi(strings.ReplaceAll(strings.ReplaceAll(path, "x", ""), "/", ""))
	if err != nil {
		l.t.Errorf("bad tile path %q", path)
		return
	}
	width := 256
	if isPartial {
		width, _ = strconv.Atoi(partial)
	}
	first := n * 256
	if first+width > len(l.names) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Encoding", "gzip")
	z := gzip.NewWriter(w)
	defer z.Close()
	for i, name := range l.names[first : first+width] {
		entry, _ := json.Marshal(map[string]any{"Timestamp": 1753375092043 + i, "Subject": map[string]string{"CommonName": name}, "DNS": []string{name, "www." + name}})
		z.Write(append(entry, '\n'))
	}
}

func (l *fakeLog) reader() *robertparker.CTReader {
	return &robertparker.CTReader{List: l.server.URL + "/list.json", Poll: time.Millisecond, Wait: time.Hour}
}

func (l *fakeLog) log() robertparker.CTLog {
	return robertparker.CTLog{Name: "Test log", URL: l.server.URL}
}

// following runs reader until stop returns true of what's been seen, and returns that.
func (l *fakeLog) following(t *testing.T, r *robertparker.CTReader, afterStart func(), stop func([]string) bool) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var mu sync.Mutex
	var seen []string
	done := make(chan error, 1)
	go func() {
		done <- r.Names(ctx, func(s robertparker.Sighting) {
			mu.Lock()
			defer mu.Unlock()
			if !strings.HasPrefix(s.Name, "www.") {
				seen = append(seen, s.Name)
			}
			if stop(seen) {
				cancel()
			}
		})
	}()
	l.awaitTail(ctx)
	afterStart()
	if err := <-done; err != context.Canceled {
		t.Errorf("got %v, and saw %d names", err, len(seen))
	}
	return seen
}

func TestCTLogsFromList(t *testing.T) {
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name       string
		start, end time.Time
		state      string
		want       bool
	}{
		{"current", now.Add(-time.Hour), now.Add(time.Hour), "usable", true},
		{"qualified", now.Add(-time.Hour), now.Add(time.Hour), "qualified", true},
		{"for certificates issued now that expire later", now.Add(100 * 24 * time.Hour), now.Add(280 * 24 * time.Hour), "usable", true},
		{"too far ahead", now.Add(300 * 24 * time.Hour), now.Add(400 * 24 * time.Hour), "usable", false},
		{"expired", now.Add(-48 * time.Hour), now.Add(-time.Hour), "usable", false},
		{"retired", now.Add(-time.Hour), now.Add(time.Hour), "retired", false},
		{"read only", now.Add(-time.Hour), now.Add(time.Hour), "readonly", false},
	} {
		l := newFakeLog(t, 300)
		l.locked(func() { l.interval, l.state = [2]time.Time{tt.start, tt.end}, tt.state })
		r := l.reader()
		r.Now = func() time.Time { return now }
		logs, err := r.Logs(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if tt.want != (len(logs) == 1) {
			t.Errorf("%s: got %+v", tt.name, logs)
		}
		if len(logs) == 1 && (logs[0].Name != "Test log" || logs[0].URL != l.server.URL) {
			t.Errorf("%s: got %+v", tt.name, logs[0])
		}
	}
}

func TestCTLogsLeaveOutLogsWithoutNamesTiles(t *testing.T) {
	l := newFakeLog(t, 300)
	l.locked(func() { l.noTiles = true })
	r := l.reader()
	logs, err := r.Logs(context.Background())
	if err != nil || len(logs) != 0 {
		t.Errorf("got %+v, %v", logs, err)
	}
	if err := r.Names(context.Background(), func(robertparker.Sighting) {}); err == nil {
		t.Error("with no logs to read, Names should say so")
	}
}

func TestCTLogsBadList(t *testing.T) {
	l := newFakeLog(t, 300)
	l.locked(func() { l.body["/list.json"] = "not json" })
	if _, err := l.reader().Logs(context.Background()); err == nil {
		t.Error("expected an error")
	}
	l.locked(func() {
		l.gone["/list.json"] = true
		delete(l.body, "/list.json")
	})
	if _, err := l.reader().Logs(context.Background()); err == nil {
		t.Error("expected an error")
	}
}

func TestCTFollowsNewEntries(t *testing.T) {
	l := newFakeLog(t, 300)
	added := make([]string, 520)
	for i := range added {
		added[i] = fmt.Sprintf("new%d.example", i)
	}
	got := l.following(t, l.reader(), func() { l.add(added...) }, func(seen []string) bool { return len(seen) >= 212 })

	// The log started with 300 entries, so the first tile it can read holds entries 256 to 511, and it starts at 300.
	if len(got) != 212 || got[0] != "new0.example" || got[211] != "new211.example" {
		t.Errorf("got %d names: %q", len(got), got[:min(3, len(got))])
	}
	l.locked(func() {
		for agent := range l.agents {
			if !strings.HasPrefix(agent, "robertparker ") {
				t.Errorf("User-Agent %q", agent)
			}
		}
	})
}

func TestCTWaitsForFullTiles(t *testing.T) {
	l := newFakeLog(t, 256)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	l.add("a.example", "b.example")
	var seen int
	err := l.reader().Names(ctx, func(robertparker.Sighting) { seen++ })
	if err != context.DeadlineExceeded || seen != 0 {
		t.Errorf("got %v, and %d names", err, seen)
	}
	l.locked(func() {
		for path := range l.hits {
			if strings.Contains(path, ".p/") {
				t.Errorf("fetched partial tile %s", path)
			}
		}
	})
}

func TestCTReadsPartialTilesAfterWaiting(t *testing.T) {
	l := newFakeLog(t, 256)
	r := l.reader()
	r.Wait = 10 * time.Millisecond
	got := l.following(t, r, func() { l.add("a.example", "b.example") }, func(seen []string) bool { return len(seen) >= 2 })
	if !slices.Equal(got, []string{"a.example", "b.example"}) {
		t.Fatalf("got %q", got)
	}

	// Once the tile fills, only what's new should be sent.
	l = newFakeLog(t, 256)
	r = l.reader()
	r.Wait = 10 * time.Millisecond
	more := make([]string, 254)
	for i := range more {
		more[i] = fmt.Sprintf("more%d.example", i)
	}
	got = l.following(t, r, func() {
		l.add("a.example", "b.example")
		time.Sleep(100 * time.Millisecond)
		l.add(more...)
	}, func(seen []string) bool { return len(seen) >= 256 })
	if len(got) != 256 || got[0] != "a.example" || got[2] != "more0.example" || got[255] != "more253.example" {
		t.Errorf("got %d names, starting %q", len(got), got[:min(3, len(got))])
	}
}

func TestCTPartialTileThatsGone(t *testing.T) {
	l := newFakeLog(t, 256)
	l.locked(func() { l.gone["/tile/names/001.p/2"] = true })
	r := l.reader()
	r.Wait = 10 * time.Millisecond
	more := make([]string, 254)
	got := l.following(t, r, func() {
		l.add("a.example", "b.example")
		time.Sleep(50 * time.Millisecond)
		for i := range more {
			more[i] = fmt.Sprintf("more%d.example", i)
		}
		l.add(more...)
	}, func(seen []string) bool { return len(seen) >= 256 })
	if len(got) != 256 || got[0] != "a.example" {
		t.Errorf("got %d names", len(got))
	}
}

func TestCTKeepsTryingWithoutLosingEntries(t *testing.T) {
	l := newFakeLog(t, 256)
	l.locked(func() { l.missing["/tile/names/001"] = 1 })
	var mu sync.Mutex
	var problems []string
	r := l.reader()
	r.Report = func(log string, err error) {
		mu.Lock()
		defer mu.Unlock()
		problems = append(problems, log+": "+err.Error())
	}
	more := make([]string, 256)
	for i := range more {
		more[i] = fmt.Sprintf("more%d.example", i)
	}
	got := l.following(t, r, func() { l.add(more...) }, func(seen []string) bool { return len(seen) >= 256 })
	if len(got) != 256 || got[0] != "more0.example" {
		t.Errorf("got %d names", len(got))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(problems) != 1 || !strings.Contains(problems[0], "Test log") || !strings.Contains(problems[0], "503") {
		t.Errorf("problems: %q", problems)
	}
}

func TestCTKeepsPlaceAfterABadEntry(t *testing.T) {
	l := newFakeLog(t, 256)
	var tile strings.Builder
	for i := range 255 {
		fmt.Fprintf(&tile, `{"Timestamp": 1, "DNS": ["%d.example"]}`+"\n", i)
	}
	l.locked(func() { l.body["/tile/names/001"] = "not json\n" + tile.String() })
	more := make([]string, 256)
	for i := range more {
		more[i] = "x.example"
	}
	got := l.following(t, l.reader(), func() { l.add(more...) }, func(seen []string) bool { return len(seen) >= 255 })
	if len(got) != 255 || got[0] != "0.example" {
		t.Errorf("got %d names, starting %q", len(got), got[:min(1, len(got))])
	}
}

func TestCTTilePaths(t *testing.T) {
	for n, want := range map[int64]string{0: "000", 5: "005", 999: "999", 1000: "x001/000", 1234067: "x001/x234/067", 3760965: "x003/x760/965"} {
		if got := robertparker.TilePath(n); got != want {
			t.Errorf("%d: got %s, want %s", n, got, want)
		}
	}
}

func TestCTSightings(t *testing.T) {
	l := newFakeLog(t, 256)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := l.reader()
	var got []robertparker.Sighting
	var mu sync.Mutex
	go func() {
		l.awaitTail(ctx)
		names := make([]string, 256)
		for i := range names {
			names[i] = "a.example"
		}
		l.add(names...)
	}()
	r.Names(ctx, func(s robertparker.Sighting) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, s)
		cancel()
	})
	if len(got) == 0 {
		t.Fatal("nothing seen")
	}
	if got[0].Name != "a.example" || got[0].Source != "Test log" || got[0].Seen.UnixMilli() != 1753375092043 {
		t.Errorf("got %+v", got[0])
	}
}
