// Package metrics is the one metrics registry (golden signals, LOG-10),
// exposed in Prometheus text format on the internal listener. It is
// deliberately tiny and dependency-free: counters, gauges and fixed-bucket
// histograms keyed by a sorted label set.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
)

var defaultBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type series struct {
	labels  string
	value   float64
	buckets []uint64
	sum     float64
	count   uint64
}

type family struct {
	name, help, kind string
	series           map[string]*series
}

// Registry holds metric families.
type Registry struct {
	mu       sync.Mutex
	families map[string]*family
	gauges   map[string]func() float64
}

// Default is the process registry.
var Default = &Registry{families: map[string]*family{}, gauges: map[string]func() float64{}}

func labelString(kv []string) string {
	if len(kv) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		v := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(kv[i+1])
		pairs = append(pairs, kv[i]+`="`+v+`"`)
	}
	sort.Strings(pairs)
	return "{" + strings.Join(pairs, ",") + "}"
}

func (r *Registry) get(name, help, kind, labels string) *series {
	f, ok := r.families[name]
	if !ok {
		f = &family{name: name, help: help, kind: kind, series: map[string]*series{}}
		r.families[name] = f
	}
	s, ok := f.series[labels]
	if !ok {
		s = &series{labels: labels}
		if kind == "histogram" {
			s.buckets = make([]uint64, len(defaultBuckets))
		}
		f.series[labels] = s
	}
	return s
}

// Inc adds 1 to a counter.
func (r *Registry) Inc(name, help string, labels ...string) { r.Add(name, help, 1, labels...) }

// Add adds v to a counter.
func (r *Registry) Add(name, help string, v float64, labels ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.get(name, help, "counter", labelString(labels)).value += v
}

// Observe records a histogram sample (seconds).
func (r *Registry) Observe(name, help string, v float64, labels ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.get(name, help, "histogram", labelString(labels))
	for i, b := range defaultBuckets {
		if v <= b {
			s.buckets[i]++
		}
	}
	s.sum += v
	s.count++
}

// GaugeFunc registers a gauge read at scrape time.
func (r *Registry) GaugeFunc(name, help string, fn func() float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gauges[name+"\x00"+help] = fn
}

// Write renders the registry in Prometheus text exposition format.
func (r *Registry) Write(w io.Writer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.families))
	for n := range r.families {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f := r.families[n]
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", f.name, f.help, f.name, f.kind)
		keys := make([]string, 0, len(f.series))
		for k := range f.series {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s := f.series[k]
			if f.kind == "counter" {
				fmt.Fprintf(w, "%s%s %g\n", f.name, s.labels, s.value)
				continue
			}
			inner := strings.TrimSuffix(strings.TrimPrefix(s.labels, "{"), "}")
			sep := ""
			if inner != "" {
				sep = ","
			}
			for i, b := range defaultBuckets {
				fmt.Fprintf(w, "%s_bucket{%s%sle=\"%g\"} %d\n", f.name, inner, sep, b, s.buckets[i])
			}
			fmt.Fprintf(w, "%s_bucket{%s%sle=\"+Inf\"} %d\n", f.name, inner, sep, s.count)
			fmt.Fprintf(w, "%s_sum%s %g\n%s_count%s %d\n", f.name, s.labels, s.sum, f.name, s.labels, s.count)
		}
	}
	gk := make([]string, 0, len(r.gauges))
	for k := range r.gauges {
		gk = append(gk, k)
	}
	sort.Strings(gk)
	for _, k := range gk {
		name, help, _ := strings.Cut(k, "\x00")
		v := r.gauges[k]()
		if math.IsNaN(v) {
			continue
		}
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, v)
	}
}
