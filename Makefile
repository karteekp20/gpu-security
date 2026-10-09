BINARY  := ray-guard
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X gpusecurity/internal/domain.Version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

# A single static binary is a product requirement, not a build preference:
# it is what makes ray-guard runnable on an air-gapped host and handable to a
# security lead who will run it once, in 60 seconds (CLAUDE.md P4, 15).
GOFLAGS_STATIC := CGO_ENABLED=0

.PHONY: build build-all test test-p3 test-integration demo demo-up demo-down lint fmt run report-pdf sbom airgap-bundle clean

# The demo subnet is pinned in test/integration/docker-compose.yml.
DEMO_SUBNET := 172.31.77.0/24

build:
	$(GOFLAGS_STATIC) go build -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/$(BINARY)

## build-all: cross-compile the release matrix into bin/
build-all:
	@mkdir -p bin
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		echo "  $$os/$$arch"; \
		$(GOFLAGS_STATIC) GOOS=$$os GOARCH=$$arch \
			go build -ldflags '$(LDFLAGS)' -o bin/$(BINARY)-$$os-$$arch ./cmd/$(BINARY) || exit 1; \
	done
	@cd bin && sha256sum $(BINARY)-* > SHA256SUMS

test:
	go test -race ./...

## test-p3: the metadata-only enforcement suite (CLAUDE.md P3). Never skip.
test-p3:
	go test -race -v ./test/...

## test-integration: run the detections against REAL services in docker.
## Unit tests only prove our logic agrees with our own mocks; this proves
## RG-RAY-001 fires against actual Ray. Heavy images - not part of `make test`.
test-integration:
	@cd test/integration && \
	if ! docker compose version >/dev/null 2>&1; then \
		echo "docker compose unavailable."; \
		echo "If this says 'client version is too old', your compose plugin predates"; \
		echo "the daemon. Upgrade it, or work around it with:"; \
		echo "    DOCKER_API_VERSION=1.44 make test-integration"; \
		exit 1; \
	fi; \
	trap 'docker compose down -v --remove-orphans >/dev/null 2>&1' EXIT; \
	docker compose up -d --wait --wait-timeout 300 || \
		{ docker compose logs --tail=40; exit 1; }; \
	./wait-ready.sh && \
	RAY_GUARD_INTEGRATION=1 go test -tags=integration -count=1 -v ./...

## demo-up: start the deliberately-insecure cluster used for live demos.
## Run this BEFORE a call - Ray takes 30-60s to bind its dashboard, and that
## is not silence you want on a screenshare. See docs/assessment/demo.md.
demo-up:
	@cd test/integration && \
	if ! docker compose version >/dev/null 2>&1; then \
		echo "docker compose unavailable. If it reports 'client version is too old',"; \
		echo "try: DOCKER_API_VERSION=1.44 make demo-up"; \
		exit 1; \
	fi; \
	docker compose up -d --wait --wait-timeout 300 >/dev/null || \
		{ docker compose logs --tail=40; exit 1; }; \
	./wait-ready.sh
	@echo
	@echo "Demo cluster up on $(DEMO_SUBNET). Run 'make demo' to scan it."
	@echo "Tear down with 'make demo-down' when you are finished."

## demo: scan the demo cluster and write the report. ~16s (a /24 at -timeout 2s
## is bounded by 8 waves of 32 hosts; measured 16.3s).
demo: build
	@./bin/$(BINARY) -cidr $(DEMO_SUBNET) -timeout 2s -out ./report || true
	@echo
	@echo "Open ./report/report.html to walk through it on screen."

## demo-down: stop the demo cluster and remove its network and volumes.
demo-down:
	@cd test/integration && docker compose down -v --remove-orphans >/dev/null 2>&1 || true
	@echo "demo cluster removed"

lint:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed in:"; echo "$$unformatted"; exit 1; \
	fi
	go vet ./...
	@command -v golangci-lint >/dev/null 2>&1 \
		&& golangci-lint run \
		|| echo "golangci-lint not installed; ran gofmt + go vet only"

fmt:
	gofmt -w .

run: build
	./bin/$(BINARY) -targets $(TARGETS)

## report-pdf: render an existing report.html to PDF via headless Chrome.
## The scanner itself stays dependency-free; PDF is an optional local step.
report-pdf:
	@in=$${IN:-./report/report.html}; out=$${OUT:-./report/report.pdf}; \
	browser=$$(command -v google-chrome || command -v google-chrome-stable || command -v chromium || command -v chromium-browser); \
	if [ -z "$$browser" ]; then \
		echo "no Chrome/Chromium found; open $$in and print to PDF instead"; exit 1; \
	fi; \
	"$$browser" --headless --disable-gpu --no-sandbox --no-pdf-header-footer \
		--print-to-pdf="$$out" "file://$$(realpath $$in)" && echo "wrote $$out"

## sbom: CycloneDX SBOM for every build (CLAUDE.md P8, 12).
sbom:
	@mkdir -p bin
	@command -v syft >/dev/null 2>&1 \
		|| { echo "syft not installed: https://github.com/anchore/syft"; exit 1; }
	syft scan dir:. -o cyclonedx-json=bin/sbom.cyclonedx.json
	@echo "wrote bin/sbom.cyclonedx.json"

## airgap-bundle: signed offline update bundle. Phase 1 (CLAUDE.md 13).
airgap-bundle:
	@echo "not built yet: the signed air-gap manifest lands with the rule library in Phase 1 (CLAUDE.md 13, 14)"

clean:
	rm -rf bin report
