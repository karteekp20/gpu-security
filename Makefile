BINARY := ray-guard

.PHONY: build test lint run clean
build:
	CGO_ENABLED=0 go build -o bin/$(BINARY) ./cmd/ray-guard
test:
	go test -race ./...
lint:
	gofmt -l . && go vet ./...
run: build
	./bin/$(BINARY) -targets $(TARGETS)
clean:
	rm -rf bin report
