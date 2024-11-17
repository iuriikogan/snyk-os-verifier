GOLANG_VERSION := 1.23.2

.PHONY: build
build:
	go mod download
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o bin/snyk-os-verifier .

.PHONY: test
test:
	go test ./... -v --count=0

.PHONY: vet
vet:
	go vet ./...

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: clean
clean:
	rm -f bin/ratify-snyk-verifier
	rm -f coverage.out
