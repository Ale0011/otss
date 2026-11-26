// Package metrics exposes Prometheus text format with no external dependency.
// Counters are global aggregates only — no per-secret labels or values.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Counter is a monotonically increasing counter.
type Counter struct {
	name string
	help string
	mu   sync.RWMutex
	vals map[string]*uint64
}

// Inc increments the counter for labelValue.
func (c *Counter) Inc(labelValue string) {
	c.mu.RLock()
	p, ok := c.vals[labelValue]
	c.mu.RUnlock()
	if !ok {
		c.mu.Lock()
		p, ok = c.vals[labelValue]
		if !ok {
			p = new(uint64)
			c.vals[labelValue] = p
		}
		c.mu.Unlock()
	}
	atomic.AddUint64(p, 1)
}

// Add increments by n.
func (c *Counter) Add(labelValue string, n uint64) {
	c.mu.RLock()
	p, ok := c.vals[labelValue]
	c.mu.RUnlock()
	if !ok {
		c.mu.Lock()
		p, ok = c.vals[labelValue]
		if !ok {
			p = new(uint64)
			c.vals[labelValue] = p
		}
		c.mu.Unlock()
	}
	atomic.AddUint64(p, n)
}

var latencyBuckets = []float64{
	0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5,
}

// Histogram collects latency samples in seconds.
type Histogram struct {
	name   string
	help   string
	mu     sync.Mutex
	counts []uint64
	sum    float64
	total  uint64
}

// Observe records one sample.
func (h *Histogram) Observe(seconds float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sum += seconds
	h.total++
	for i, b := range latencyBuckets {
		if seconds <= b {
			h.counts[i]++
			return
		}
	}
	h.counts[len(latencyBuckets)]++
}

type gaugeEntry struct {
	help string
	fn   func() int64
}

// Registry holds the metric set for one process.
type Registry struct {
	start time.Time

	mu       sync.RWMutex
	counters map[string]*Counter
	gauges   map[string]gaugeEntry
	histos   map[string]*Histogram
	order    []string
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{
		start:    time.Now(),
		counters: make(map[string]*Counter),
		gauges:   make(map[string]gaugeEntry),
		histos:   make(map[string]*Histogram),
	}
}

// Counter registers or returns a counter.
func (r *Registry) Counter(name, help string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.counters[name]; ok {
		return c
	}
	c := &Counter{name: name, help: help, vals: make(map[string]*uint64)}
	r.counters[name] = c
	r.order = append(r.order, name)
	return c
}

// Gauge registers a callback-backed gauge.
func (r *Registry) Gauge(name, help string, fn func() int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gauges[name] = gaugeEntry{help: help, fn: fn}
	r.order = append(r.order, name)
}

// Histogram registers a latency histogram.
func (r *Registry) Histogram(name, help string) *Histogram {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.histos[name]; ok {
		return h
	}
	h := &Histogram{name: name, help: help, counts: make([]uint64, len(latencyBuckets)+1)}
	r.histos[name] = h
	r.order = append(r.order, name)
	return h
}

// WriteTo renders the registry in Prometheus text exposition format.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	var n int64
	wr := func(format string, args ...any) {
		c, _ := fmt.Fprintf(w, format, args...)
		n += int64(c)
	}

	r.mu.RLock()
	order := append([]string(nil), r.order...)
	r.mu.RUnlock()

	for _, name := range order {
		r.mu.RLock()
		c, isC := r.counters[name]
		g, isG := r.gauges[name]
		h, isH := r.histos[name]
		r.mu.RUnlock()

		switch {
		case isC:
			wr("# HELP %s %s\n# TYPE %s counter\n", c.name, c.help, c.name)
			c.mu.RLock()
			keys := make([]string, 0, len(c.vals))
			for k := range c.vals {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := atomic.LoadUint64(c.vals[k])
				if k == "" {
					wr("%s %d\n", c.name, v)
				} else {
					wr("%s{ip=%s} %d\n", c.name, quote(k), v)
				}
			}
			c.mu.RUnlock()

		case isH:
			wr("# HELP %s %s\n# TYPE %s histogram\n", h.name, h.help, h.name)
			h.mu.Lock()
			var cumulative uint64
			for i, b := range latencyBuckets {
				cumulative += h.counts[i]
				wr("%s_bucket{le=%s} %d\n", h.name, quote(strconv.FormatFloat(b, 'g', -1, 64)), cumulative)
			}
			cumulative += h.counts[len(latencyBuckets)]
			wr("%s_bucket{le=\"+Inf\"} %d\n", h.name, cumulative)
			wr("%s_sum %s\n", h.name, strconv.FormatFloat(h.sum, 'g', -1, 64))
			wr("%s_count %d\n", h.name, h.total)
			h.mu.Unlock()

		case isG:
			wr("# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, g.help, name, name, g.fn())
		}
	}

	wr("# HELP otss_uptime_seconds Process uptime in seconds\n# TYPE otss_uptime_seconds gauge\notss_uptime_seconds %s\n",
		strconv.FormatFloat(time.Since(r.start).Seconds(), 'g', -1, 64))

	return n, nil
}

func quote(s string) string {
	out := make([]byte, 0, len(s)+2)
	out = append(out, '"')
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			out = append(out, '\\', '\\')
		case '"':
			out = append(out, '\\', '"')
		case '\n':
			out = append(out, '\\', 'n')
		default:
			out = append(out, s[i])
		}
	}
	return string(append(out, '"'))
}
