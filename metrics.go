package jwtmiddleware

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics is a generic metrics interface for the middleware.
type Metrics interface {
	IncCounter(name string, tags map[string]string)
	ObserveHistogram(name string, value float64, tags map[string]string)
	SetGauge(name string, value float64, tags map[string]string)
}

// NoopMetrics is a default metrics implementation that does nothing.
type NoopMetrics struct{}

func (m *NoopMetrics) IncCounter(name string, tags map[string]string)                      {}
func (m *NoopMetrics) ObserveHistogram(name string, value float64, tags map[string]string) {}
func (m *NoopMetrics) SetGauge(name string, value float64, tags map[string]string)         {}

// PrometheusMetrics implements the Metrics interface using Prometheus.
type PrometheusMetrics struct {
	counters   map[string]*prometheus.CounterVec
	histograms map[string]*prometheus.HistogramVec
	gauges     map[string]*prometheus.GaugeVec
}

// NewPrometheusMetrics returns a Metrics implementation backed by Prometheus.
func NewPrometheusMetrics() Metrics {
	return &PrometheusMetrics{
		counters:   make(map[string]*prometheus.CounterVec),
		histograms: make(map[string]*prometheus.HistogramVec),
		gauges:     make(map[string]*prometheus.GaugeVec),
	}
}

func (m *PrometheusMetrics) IncCounter(name string, tags map[string]string) {
	vec, ok := m.counters[name]
	if !ok {
		vec = prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: name + " counter"}, keys(tags))
		prometheus.MustRegister(vec)
		m.counters[name] = vec
	}
	vec.With(tags).Inc()
}

func (m *PrometheusMetrics) ObserveHistogram(name string, value float64, tags map[string]string) {
	vec, ok := m.histograms[name]
	if !ok {
		vec = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: name, Help: name + " histogram"}, keys(tags))
		prometheus.MustRegister(vec)
		m.histograms[name] = vec
	}
	vec.With(tags).Observe(value)
}

func (m *PrometheusMetrics) SetGauge(name string, value float64, tags map[string]string) {
	vec, ok := m.gauges[name]
	if !ok {
		vec = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: name + " gauge"}, keys(tags))
		prometheus.MustRegister(vec)
		m.gauges[name] = vec
	}
	vec.With(tags).Set(value)
}

func keys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
