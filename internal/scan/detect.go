package scan

import (
	"fmt"

	"gpusecurity/internal/domain"
)

type ruleDef struct {
	ruleID      string
	title       string
	severity    domain.Severity
	remediation string
	cves        []string
}

var rules = map[string]ruleDef{
	"ray-dashboard": {"RG-RAY-001", "Unauthenticated Ray dashboard / Jobs API exposed", domain.Critical,
		"Enable Ray authentication or bind the dashboard to loopback/a private subnet; never expose port 8265 publicly.",
		[]string{"CVE-2023-48022", "CVE-2025-62593"}},
	"ray-client": {"RG-RAY-002", "Ray client server port reachable", domain.High,
		"Restrict the Ray client port (10001) to trusted networks only.", nil},
	"vllm": {"RG-VLLM-001", "Unauthenticated vLLM inference API exposed", domain.High,
		"Place vLLM behind an authenticated gateway; do not expose the API directly.", nil},
	"triton": {"RG-TRITON-001", "Unauthenticated NVIDIA Triton server exposed", domain.High,
		"Restrict Triton HTTP/gRPC endpoints to trusted networks; add an auth proxy.", nil},
	"triton-metrics": {"RG-TRITON-002", "Triton metrics endpoint publicly reachable", domain.Low,
		"Restrict the metrics port (8002) to your monitoring network.", nil},
	"mlflow": {"RG-MLFLOW-001", "Unauthenticated MLflow server exposed", domain.High,
		"Put MLflow behind authentication; restrict network exposure.", nil},
	"jupyter": {"RG-JUPYTER-001", "Jupyter server reachable without token/auth", domain.High,
		"Require a token/password on Jupyter; do not bind to 0.0.0.0 on untrusted networks.", nil},
	"ollama": {"RG-OLLAMA-001", "Unauthenticated Ollama API exposed", domain.Medium,
		"Restrict the Ollama API (11434) to localhost/trusted networks.", nil},
	"slurmctld": {"RG-SLURM-001", "Slurm controller port reachable", domain.Medium,
		"Restrict slurmctld (6817) to the cluster management network only.", nil},
}

// Detect turns benign observations into findings.
func Detect(obs []domain.Observation) []domain.Finding {
	var findings []domain.Finding
	for _, o := range obs {
		r, ok := rules[o.Service]
		if !ok {
			continue
		}
		if o.HTTPStatus == 0 {
			findings = append(findings, mkFinding(r, o, fmt.Sprintf("Port %d reachable. %s", o.Port, o.Note)))
			continue
		}
		if o.Unauth {
			detail := fmt.Sprintf("HTTP %d without authentication on port %d", o.HTTPStatus, o.Port)
			f := mkFinding(r, o, detail)
			if !o.TLS {
				f.Detail += " (no TLS)"
			}
			findings = append(findings, f)
		}
	}
	return findings
}

func mkFinding(r ruleDef, o domain.Observation, detail string) domain.Finding {
	return domain.Finding{
		RuleID: r.ruleID, Title: r.title, Severity: r.severity,
		Host: o.Host, Port: o.Port, Service: o.Service,
		Detail: detail, Remediation: r.remediation, CVEs: r.cves,
	}
}
