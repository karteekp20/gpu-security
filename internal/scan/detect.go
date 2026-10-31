package scan

import (
	"fmt"
	"net/http"

	"gpusecurity/internal/domain"
)

type ruleDef struct {
	ruleID      string
	title       string
	severity    domain.Severity
	remediation string
	cves        []string
}

// A title states what was OBSERVED, never what was inferred about exposure.
// The scanner learns reachability from one vantage; it cannot learn internet
// exposure, which is why ScanResult records ScannedFrom. Four titles used to
// say "publicly reachable" and were factually wrong on every RFC 1918 scan -
// including the demo stack's own 172.31.77.0/24 - in the single most-read
// string in the report. "Internet-exposed" is a claim for something
// independently verified, which L1 never does.
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
	"triton-grpc": {"RG-TRITON-003", "NVIDIA Triton gRPC endpoint reachable", domain.Medium,
		"Restrict the Triton gRPC port (8001) to trusted networks; front it with an auth proxy.", nil},
	"triton-metrics": {"RG-TRITON-002", "Triton metrics endpoint reachable without authentication", domain.Low,
		"Restrict the metrics port (8002) to your monitoring network.", nil},
	"mlflow": {"RG-MLFLOW-001", "Unauthenticated MLflow server exposed", domain.High,
		"Put MLflow behind authentication; restrict network exposure.", nil},
	"jupyter": {"RG-JUPYTER-001", "Jupyter server reachable without token/auth", domain.High,
		"Require a token/password on Jupyter; do not bind to 0.0.0.0 on untrusted networks.", nil},
	"ollama": {"RG-OLLAMA-001", "Unauthenticated Ollama API exposed", domain.Medium,
		"Restrict the Ollama API (11434) to localhost/trusted networks.", nil},
	"slurmctld": {"RG-SLURM-001", "Slurm controller port reachable", domain.Medium,
		"Restrict slurmctld (6817) to the cluster management network only.", nil},
	// Critical for the same reason as Ray: this is not a hardening gap. The
	// management API registers a model from any URL the caller names, so
	// reachability is execution.
	//
	// The remediation names token authorization deliberately. TorchServe
	// enforces it by default (0.12+), and it answers 400 - not 2xx - when a
	// token is required, so this rule can only fire where it was switched off
	// with --disable-token-auth or where the build predates it. Saying "it has
	// no authentication" would be wrong for current versions and corrected by
	// the first TorchServe operator in the room. Upstream is also archived
	// ("no planned updates, bug fixes, new features, or security patches"),
	// which is why network isolation, not a version bump, is the durable fix.
	"torchserve-mgmt": {"RG-TORCHSERVE-001", "Unauthenticated TorchServe management API exposed", domain.Critical,
		"This answered without a token, so token authorization is disabled (--disable-token-auth) or this build predates it: re-enable it, bind the management API (8081) to loopback, and set allowed_urls to the registries you actually use. Note that the official pytorch/torchserve image ships a config.properties binding inference, management, metrics and both gRPC addresses to 0.0.0.0, so a container run from it is exposed on every interface by default. Upstream TorchServe is archived and will get no further security patches, so network isolation is the durable control rather than an upgrade.",
		[]string{"CVE-2023-43654"}},
	"torchserve-metrics": {"RG-TORCHSERVE-002", "TorchServe metrics endpoint reachable without authentication", domain.Low,
		"Restrict the metrics port (8082) to your monitoring network.", nil},
	"sglang": {"RG-SGLANG-001", "Unauthenticated SGLang inference API exposed", domain.High,
		"Place SGLang behind an authenticated gateway; bind --host to loopback or a private address rather than exposing port 30000.", nil},
	// Medium, not low, and the distinction is the point: this is not one
	// service's counters like Triton's or TorchServe's metrics port. DCGM
	// labels per-GPU utilization with the pod, namespace and container using
	// each device, so an exposed exporter is a workload inventory of every
	// tenant on the node - which is the cross-tenant visibility this product
	// exists to talk about.
	"dcgm-exporter": {"RG-DCGM-001", "NVIDIA DCGM exporter reachable without authentication", domain.Medium,
		"Restrict port 9400 to your monitoring network (in Kubernetes, a ClusterIP service with internalTrafficPolicy: Local rather than a NodePort). The metrics name the pod and namespace using each GPU, so this enumerates tenant workloads.", nil},
}

var (
	ruleTLSInvalid = ruleDef{"RG-TLS-001", "TLS certificate fails verification", domain.Medium,
		"Replace the certificate with one issued by a trusted CA, matching the service hostname and within its validity window.", nil}
	ruleTLSPlaintext = ruleDef{"RG-TLS-002", "Authenticated service served over plaintext HTTP", domain.Medium,
		"Terminate TLS in front of this service; credentials sent to it currently traverse the network in the clear.", nil}
	// Medium for the same reason as a bad certificate: the traffic is not
	// meaningfully protected. TLS 1.0/1.1 have been deprecated since RFC 8996
	// and are below the floor every current baseline sets, which also makes
	// this the TLS finding most likely to be raised by the customer's own
	// auditor if we miss it.
	ruleTLSObsolete = ruleDef{"RG-TLS-003", "Obsolete TLS version negotiated", domain.Medium,
		"Disable TLS 1.0 and 1.1 on this listener and require TLS 1.2 or later (RFC 8996); on a terminating proxy this is one directive.", nil}
	ruleBucketPublic = ruleDef{"RG-BUCKET-001", "Object storage bucket lists without authentication", domain.High,
		"Remove public-read/list permissions from the bucket and require authenticated access.", nil}
	ruleUnknownExposure = ruleDef{"RG-EXPOSURE-001", "Unidentified service reachable on an AI-infrastructure port", domain.Info,
		"Confirm what is listening on this port and whether it should be reachable from the scan vantage point.", nil}
)

// Detect turns benign observations into findings. It reasons only over
// exposure, auth state, and transport posture - never over response content.
func Detect(obs []domain.Observation) []domain.Finding {
	var findings []domain.Finding
	for _, o := range obs {
		findings = append(findings, detectOne(o)...)
	}
	return domain.SortFindings(findings)
}

// detectOne returns every finding an observation raises. Transport is the one
// case that can raise more than one: a bad certificate and an obsolete
// protocol version are separate problems with separate fixes, and they travel
// together in the field - the box with TLS 1.0 on it usually has a
// self-signed certificate too. Reporting only the certificate would mean the
// operator fixes it, re-scans, and only then learns about the protocol.
func detectOne(o domain.Observation) []domain.Finding {
	switch o.Service {
	case ServiceTLS:
		var out []domain.Finding
		if o.TLS.Issue != "" {
			detail := fmt.Sprintf("Certificate on port %d is %s", o.Port, o.TLS.Issue)
			if o.TLS.NotAfter != "" {
				detail += fmt.Sprintf(" (expires %s)", o.TLS.NotAfter)
			}
			if o.TLS.Version != "" {
				detail += fmt.Sprintf(", TLS %s", o.TLS.Version)
			}
			out = append(out, mkFinding(ruleTLSInvalid, o, detail))
		}
		if o.TLS.ObsoleteTLS() {
			out = append(out, mkFinding(ruleTLSObsolete, o,
				fmt.Sprintf("Port %d negotiated TLS %s, which is deprecated (RFC 8996)",
					o.Port, o.TLS.Version)))
		}
		return out

	case ServiceBucket:
		if !o.Unauth {
			return nil
		}
		return one(mkFinding(ruleBucketPublic, o,
			fmt.Sprintf("Unauthenticated request to the bucket endpoint returned HTTP %d. "+
				"Listing was not read - the status alone shows it is public.", o.HTTPStatus)))

	case ServiceUnknown:
		detail := fmt.Sprintf("Port %d is open but no probe identified the service", o.Port)
		if o.HTTPStatus > 0 {
			detail += fmt.Sprintf(" (HTTP %d)", o.HTTPStatus)
		}
		return one(mkFinding(ruleUnknownExposure, o, detail))
	}

	r, ok := rules[o.Service]
	if !ok {
		return nil
	}

	// A reachability-only (TCP) check: no HTTP response to reason about.
	if o.HTTPStatus == 0 {
		return one(mkFinding(r, o, fmt.Sprintf("Port %d is reachable (%s)", o.Port, o.Note)))
	}

	if o.Unauth {
		detail := fmt.Sprintf("HTTP %d without authentication on port %d", o.HTTPStatus, o.Port)
		f := mkFinding(r, o, detail)
		if !o.TLS.Enabled {
			f.Detail += " (no TLS)"
		}
		return one(f)
	}

	// Auth is enforced, but credentials cross the wire in plaintext.
	if (o.HTTPStatus == http.StatusUnauthorized || o.HTTPStatus == http.StatusForbidden) && !o.TLS.Enabled {
		return one(mkFinding(ruleTLSPlaintext, o,
			fmt.Sprintf("%s on port %d requires authentication but is served over plaintext HTTP", o.Service, o.Port)))
	}

	return nil
}

func one(f domain.Finding) []domain.Finding { return []domain.Finding{f} }

func mkFinding(r ruleDef, o domain.Observation, detail string) domain.Finding {
	return domain.Finding{
		RuleID: r.ruleID, Title: r.title, Severity: r.severity,
		Host: o.Host, Port: o.Port, Service: o.Service,
		Detail: detail, Remediation: r.remediation, CVEs: r.cves,
	}
}
