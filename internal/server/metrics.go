package server

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Metrics is a minimal Prometheus text-format registry. It supports gauges and
// counters with at most one label, which covers everything this server
// exports, and renders the classic `# TYPE` exposition format so a stock
// Prometheus scraper can consume /metrics without client libraries.
//
// All methods are nil-receiver safe, so callers can wire an optional metrics
// sink without guarding every call site.
type Metrics struct {
	mu       sync.Mutex
	gauges   map[string]*metricGauge
	counters map[string]*metricCounter
}

type metricGauge struct {
	help  string
	value int64
}

type metricCounter struct {
	help    string
	label   string // label key, "" for unlabeled series
	series  map[string]int64
	current int64 // only for unlabeled series
}

// NewMetrics creates an empty registry.
func NewMetrics() *Metrics {
	return &Metrics{
		gauges:   make(map[string]*metricGauge),
		counters: make(map[string]*metricCounter),
	}
}

// Gauge declares (or re-declares) a gauge metric.
func (m *Metrics) Gauge(name, help string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.gauges[name]; !ok {
		m.gauges[name] = &metricGauge{help: help}
	}
}

// SetGauge sets a gauge's value. Unknown names are recorded with empty help.
func (m *Metrics) SetGauge(name string, value int64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.gauges[name]; !ok {
		m.gauges[name] = &metricGauge{}
	}
	m.gauges[name].value = value
}

// Counter declares a counter metric. label is the single label key, or "" for
// an unlabeled counter.
func (m *Metrics) Counter(name, help, label string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.counters[name]; !ok {
		m.counters[name] = &metricCounter{help: help, label: label, series: make(map[string]int64)}
	}
}

// Inc increments a counter. For labeled counters, value selects the series.
func (m *Metrics) Inc(name, labelValue string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.counters[name]
	if !ok {
		c = &metricCounter{series: make(map[string]int64)}
		m.counters[name] = c
	}
	if c.label == "" {
		c.current++
		return
	}
	c.series[labelValue]++
}

// statusClass buckets an HTTP status into a Prometheus label value.
func statusClass(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500:
		return "5xx"
	default:
		return "other"
	}
}

// Render produces the Prometheus text exposition format, families in
// alphabetical order, series within a family sorted by label value.
func (m *Metrics) Render() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	var b strings.Builder
	names := make([]string, 0, len(m.gauges)+len(m.counters))
	for name := range m.gauges {
		names = append(names, name)
	}
	for name := range m.counters {
		if _, seen := m.gauges[name]; !seen {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	for _, name := range names {
		if g, ok := m.gauges[name]; ok {
			if g.help != "" {
				fmt.Fprintf(&b, "# HELP %s %s\n", name, g.help)
			}
			fmt.Fprintf(&b, "# TYPE %s gauge\n", name)
			fmt.Fprintf(&b, "%s %d\n", name, g.value)
			continue
		}
		c := m.counters[name]
		if c.help != "" {
			fmt.Fprintf(&b, "# HELP %s %s\n", name, c.help)
		}
		fmt.Fprintf(&b, "# TYPE %s counter\n", name)
		if c.label == "" {
			fmt.Fprintf(&b, "%s %d\n", name, c.current)
			continue
		}
		values := make([]string, 0, len(c.series))
		for v := range c.series {
			values = append(values, v)
		}
		sort.Strings(values)
		for _, v := range values {
			fmt.Fprintf(&b, "%s{%s=%q} %d\n", name, c.label, v, c.series[v])
		}
	}
	return b.String()
}
