GOLANG_VERSION := 1.23.2

.PHONY: build
build:
	go mod download
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/snyk-os .

.PHONY: test
test:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test ./... -v --count=0

.PHONY: vet
vet:
	go vet ./...

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: clean
clean:
	rm -f bin/snyk-os
	rm -f coverage.out