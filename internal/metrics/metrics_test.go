package metrics

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Result().Body)
	return string(body)
}

func TestSummaryWithDefaultLabels(t *testing.T) {
	m := New(Options{WithMethod: true, WithStatus: true, MetricType: "summary"})
	m.Observe("GET", "/x", 200, 5*time.Millisecond)
	m.Observe("GET", "/y", 200, 5*time.Millisecond)
	m.Observe("POST", "/x", 502, time.Millisecond)

	out := scrape(t, m)
	if !strings.Contains(out, `http_echo_requests_total{method="GET",status="200"} 2`) {
		t.Errorf("missing GET counter:\n%s", grepLines(out, "requests_total"))
	}
	if !strings.Contains(out, `http_echo_requests_total{method="POST",status="502"} 1`) {
		t.Errorf("missing POST counter:\n%s", grepLines(out, "requests_total"))
	}
	if !strings.Contains(out, "http_echo_request_duration_seconds_sum") {
		t.Error("missing duration summary")
	}
	if strings.Contains(out, `path=`) {
		t.Error("path label must be absent by default")
	}
	if !strings.Contains(out, "go_goroutines") {
		t.Error("Go collector missing")
	}
}

func TestHistogramWithPath(t *testing.T) {
	m := New(Options{WithMethod: true, WithStatus: true, WithPath: true, MetricType: "histogram"})
	m.Observe("GET", "/hello", 200, 10*time.Millisecond)

	out := scrape(t, m)
	if !strings.Contains(out, `http_echo_request_duration_seconds_bucket{method="GET",path="/hello",status="200"`) {
		t.Errorf("missing histogram bucket:\n%s", grepLines(out, "duration_seconds_bucket"))
	}
}

func TestNoLabels(t *testing.T) {
	m := New(Options{MetricType: "summary"})
	m.Observe("GET", "/x", 200, time.Millisecond)
	out := scrape(t, m)
	if !strings.Contains(out, "http_echo_requests_total 1") {
		t.Errorf("unlabelled counter missing:\n%s", grepLines(out, "requests_total"))
	}
}

func grepLines(s, needle string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, needle) {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}
