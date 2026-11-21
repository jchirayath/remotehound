package logx

import (
	"strings"
	"sync"
	"time"
)

// Record is one entry in the in-memory ring, shaped for the Logs screen.
type Record struct {
	Seq        uint64         `json:"seq"`
	Timestamp  time.Time      `json:"timestamp"`
	Severity   string         `json:"severity_text"`
	Body       string         `json:"body"`
	Event      string         `json:"event.name"`
	Source     string         `json:"source"`
	Attributes map[string]any `json:"attributes"`
}

// Filter selects records from the ring.
type Filter struct {
	Source    string
	MinLevel  string
	Query     string
	RequestID string
	DeviceID  string
	Limit     int
}

func (f Filter) match(r *Record) bool {
	if f.Source != "" && r.Source != f.Source {
		return false
	}
	if f.MinLevel != "" && rank(r.Severity) < rank(f.MinLevel) {
		return false
	}
	if f.RequestID != "" && r.Attributes["app.request.id"] != f.RequestID {
		return false
	}
	if f.DeviceID != "" && r.Attributes["app.device.id"] != f.DeviceID {
		return false
	}
	if f.Query != "" {
		q := strings.ToLower(f.Query)
		if !strings.Contains(strings.ToLower(r.Body), q) && !strings.Contains(strings.ToLower(r.Event), q) {
			return false
		}
	}
	return true
}

func rank(sev string) int {
	switch strings.ToUpper(sev) {
	case "DEBUG":
		return 0
	case "INFO":
		return 1
	case "WARN":
		return 2
	case "ERROR":
		return 3
	}
	return 1
}

// Ring is a fixed-size, concurrency-safe buffer with live subscribers.
type Ring struct {
	mu   sync.RWMutex
	buf  []*Record
	next int
	full bool
	seq  uint64
	subs map[chan *Record]struct{}
}

// NewRing returns a ring holding the last n records.
func NewRing(n int) *Ring {
	return &Ring{buf: make([]*Record, n), subs: map[chan *Record]struct{}{}}
}

func recordFromMap(source string, t time.Time, m map[string]any) *Record {
	r := &Record{Timestamp: t.UTC(), Source: source, Attributes: map[string]any{}}
	for k, v := range m {
		switch k {
		case "severity_text":
			r.Severity, _ = v.(string)
		case "body":
			r.Body, _ = v.(string)
		case "event.name":
			r.Event, _ = v.(string)
		case "timestamp", "severity_number", "service.name", "service.version", "deployment.environment.name":
		default:
			r.Attributes[k] = v
		}
	}
	return r
}

// Add appends a record and fans it out to subscribers (dropping for slow ones).
func (g *Ring) Add(r *Record) {
	g.mu.Lock()
	g.seq++
	r.Seq = g.seq
	g.buf[g.next] = r
	g.next = (g.next + 1) % len(g.buf)
	if g.next == 0 {
		g.full = true
	}
	subs := make([]chan *Record, 0, len(g.subs))
	for c := range g.subs {
		subs = append(subs, c)
	}
	g.mu.Unlock()
	for _, c := range subs {
		select {
		case c <- r:
		default: // a slow viewer must never block logging
		}
	}
}

// Query returns matching records, newest last, at most f.Limit (default 200).
func (g *Ring) Query(f Filter) []*Record {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	n := g.next
	if g.full {
		n = len(g.buf)
	}
	out := make([]*Record, 0, f.Limit)
	// Walk backwards from newest so Limit keeps the most recent.
	for i := 0; i < n && len(out) < f.Limit; i++ {
		idx := (g.next - 1 - i + len(g.buf)) % len(g.buf)
		if r := g.buf[idx]; r != nil && f.match(r) {
			out = append(out, r)
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Subscribe returns a channel of new records and a cancel func.
func (g *Ring) Subscribe() (<-chan *Record, func()) {
	c := make(chan *Record, 256)
	g.mu.Lock()
	g.subs[c] = struct{}{}
	g.mu.Unlock()
	return c, func() {
		g.mu.Lock()
		delete(g.subs, c)
		g.mu.Unlock()
	}
}

// Match exposes filter matching for live-tail consumers.
func (f Filter) Match(r *Record) bool { return f.match(r) }
