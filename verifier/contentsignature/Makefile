.DEFAULT_GOAL := all

# The GOPATH isn't always on the path.
GOPATH := $(shell go env GOPATH)

all: lint staticcheck vet fmt-fix test race
doc:
	go doc .
fmt-fix:
	go fmt .
lint:
	$(GOPATH)/bin/golint .
staticcheck:
	$(GOPATH)/bin/staticcheck -go 1.16 .
race:
	go test -race -covermode=atomic -count=1 .
showcoverage: test
	go tool cover -html=coverage.out
test:
	go test -v -coverprofile coverage.out -covermode=count -count=1 .
vet:
	go vet .
