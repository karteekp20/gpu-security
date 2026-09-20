package scan

import (
	"testing"

	"gpusecurity/internal/domain"
)

func TestDetectRayUnauthIsCritical(t *testing.T) {
	obs := []domain.Observation{{Host: "h", Port: 8265, Service: "ray-dashboard", Open: true, HTTPStatus: 200, Unauth: true}}
	f := Detect(obs)
	if len(f) != 1 || f[0].RuleID != "RG-RAY-001" || f[0].Severity != domain.Critical {
		t.Fatalf("expected 1 critical RG-RAY-001, got %+v", f)
	}
}

func TestDetectAuthedHTTPNoFinding(t *testing.T) {
	obs := []domain.Observation{{Host: "h", Port: 8000, Service: "vllm", Open: true, HTTPStatus: 401, Unauth: false}}
	if f := Detect(obs); len(f) != 0 {
		t.Fatalf("expected no findings for authed service, got %+v", f)
	}
}
