// Package metrics exposes the Prometheus collectors
// (docs/specification.md §11): request counter and duration under the
// http_echo namespace, with configurable label partitioning.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "http_echo"

// Options selects the label set and duration metric type.
type Options struct {
	WithMethod bool
	WithStatus bool
	WithPath   bool
	// MetricType is "summary" or "histogram" (validated by config).
	MetricType string
}

// Metrics holds the registry and collectors.
type Metrics struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec
	summary  *prometheus.SummaryVec
	histo    *prometheus.HistogramVec
	opts     Options
}

// New builds a registry with the Go/process collectors plus the request
// counter and duration collectors.
func New(opts Options) *Metrics {
	labels := make([]string, 0, 3)
	if opts.WithMethod {
		labels = append(labels, "method")
	}
	if opts.WithStatus {
		labels = append(labels, "status")
	}
	if opts.WithPath {
		labels = append(labels, "path")
	}

	m := &Metrics{registry: prometheus.NewRegistry(), opts: opts}
	m.registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	m.requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "requests_total",
		Help:      "Total number of HTTP requests handled.",
	}, labels)
	m.registry.MustRegister(m.requests)

	if opts.MetricType == "histogram" {
		m.histo = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "request_duration_seconds",
			Help:      "HTTP request duration in seconds.",
			Buckets:   prometheus.DefBuckets,
		}, labels)
		m.registry.MustRegister(m.histo)
	} else {
		m.summary = prometheus.NewSummaryVec(prometheus.SummaryOpts{
			Namespace:  namespace,
			Name:       "request_duration_seconds",
			Help:       "HTTP request duration in seconds.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		}, labels)
		m.registry.MustRegister(m.summary)
	}
	return m
}

// Handler serves the metrics endpoint.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Observe records one handled request.
func (m *Metrics) Observe(method, path string, status int, duration time.Duration) {
	labels := make(prometheus.Labels, 3)
	if m.opts.WithMethod {
		labels["method"] = method
	}
	if m.opts.WithStatus {
		labels["status"] = strconv.Itoa(status)
	}
	if m.opts.WithPath {
		labels["path"] = path
	}
	m.requests.With(labels).Inc()
	if m.histo != nil {
		m.histo.With(labels).Observe(duration.Seconds())
	} else {
		m.summary.With(labels).Observe(duration.Seconds())
	}
}
