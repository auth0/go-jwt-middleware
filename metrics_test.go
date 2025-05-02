package jwtmiddleware

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
)

func TestNoopMetrics(t *testing.T) {
	// Test that NoopMetrics methods don't panic
	metrics := &NoopMetrics{}

	metrics.IncCounter("test_counter", map[string]string{"tag": "value"})
	metrics.ObserveHistogram("test_histogram", 1.5, map[string]string{"tag": "value"})
	metrics.SetGauge("test_gauge", 2.5, map[string]string{"tag": "value"})
}

func TestPrometheusMetrics(t *testing.T) {
	// Reset the default registry to avoid conflicts with other tests
	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	// Create PrometheusMetrics
	metrics := NewPrometheusMetrics()

	// Test IncCounter
	t.Run("IncCounter", func(t *testing.T) {
		counterName := "test_counter"
		tags := map[string]string{"tag1": "value1", "tag2": "value2"}

		// Increment the counter
		metrics.IncCounter(counterName, tags)
		metrics.IncCounter(counterName, tags) // Increment again to verify it works properly

		// Check that the counter was registered and incremented
		promMetrics, ok := metrics.(*PrometheusMetrics)
		assert.True(t, ok)

		counter, ok := promMetrics.counters[counterName]
		assert.True(t, ok, "Counter should be registered")

		// Get the metric value using the Prometheus API
		metric := &dto.Metric{}
		err := counter.With(prometheus.Labels(tags)).(prometheus.Metric).Write(metric)
		assert.NoError(t, err)
		assert.Equal(t, float64(2), *metric.Counter.Value, "Counter should be incremented to 2")
	})

	// Test ObserveHistogram
	t.Run("ObserveHistogram", func(t *testing.T) {
		histName := "test_histogram"
		tags := map[string]string{"tag1": "value1"}
		value := 2.5

		// Observe the histogram
		metrics.ObserveHistogram(histName, value, tags)

		// Check that the histogram was registered
		promMetrics, ok := metrics.(*PrometheusMetrics)
		assert.True(t, ok)

		hist, ok := promMetrics.histograms[histName]
		assert.True(t, ok, "Histogram should be registered")

		// For histograms, we can't easily check the value directly
		// So we'll just verify it exists in the metrics map
		assert.NotNil(t, hist, "Histogram should be created")
	})

	// Test SetGauge
	t.Run("SetGauge", func(t *testing.T) {
		gaugeName := "test_gauge"
		tags := map[string]string{"tag1": "value1"}
		value := 4.5

		// Set the gauge
		metrics.SetGauge(gaugeName, value, tags)

		// Check that the gauge was registered
		promMetrics, ok := metrics.(*PrometheusMetrics)
		assert.True(t, ok)

		gauge, ok := promMetrics.gauges[gaugeName]
		assert.True(t, ok, "Gauge should be registered")

		// Get the metric value using the Prometheus API
		metric := &dto.Metric{}
		err := gauge.With(prometheus.Labels(tags)).(prometheus.Metric).Write(metric)
		assert.NoError(t, err)
		assert.Equal(t, value, *metric.Gauge.Value, "Gauge should be set to the specified value")
	})
}

func TestKeys(t *testing.T) {
	// Test the keys helper function
	testMap := map[string]string{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
	}

	result := keys(testMap)

	// We can't guarantee the order of keys, so we need to check that all keys are present
	assert.Equal(t, len(testMap), len(result), "Should return all keys")
	for _, k := range result {
		_, found := testMap[k]
		assert.True(t, found, "Each returned key should exist in the original map")
	}
}
