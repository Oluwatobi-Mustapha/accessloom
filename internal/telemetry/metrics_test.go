package telemetry

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNewMetricsCountersAndHistogram(t *testing.T) {
	m := NewMetrics()
	if m == nil {
		t.Fatal("metrics must not be nil")
	}

	m.ScanRunsTotal.Add(1)
	m.ScanSuccessTotal.Add(1)
	m.ScanFailureTotal.Add(1)
	m.ScanPartialTotal.Add(1)
	m.ScanInFlight.Set(0)
	m.FindingsGenerated.Add(2)
	m.ScanDurationMS.Observe(250)
	m.RepoScanRunsTotal.Add(1)
	m.RepoScanFailureTotal.Add(1)
	m.RepoScanDurationMS.Observe(300)

	if got := testutil.ToFloat64(m.ScanRunsTotal); got != 1 {
		t.Fatalf("expected scan runs 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.ScanSuccessTotal); got != 1 {
		t.Fatalf("expected scan success 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.ScanFailureTotal); got != 1 {
		t.Fatalf("expected scan failures 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.ScanPartialTotal); got != 1 {
		t.Fatalf("expected scan partial 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.FindingsGenerated); got != 2 {
		t.Fatalf("expected findings generated 2, got %v", got)
	}
	if got := testutil.ToFloat64(m.RepoScanRunsTotal); got != 1 {
		t.Fatalf("expected repo scan runs 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.RepoScanFailureTotal); got != 1 {
		t.Fatalf("expected repo scan failures 1, got %v", got)
	}
}
