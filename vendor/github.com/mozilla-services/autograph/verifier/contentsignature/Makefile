.DEFAULT_GOAL := all
all: lint vet fmt-fix test race
doc:
	go doc .
fmt-fix:
	go fmt .
lint:
	golint .
race:
	go test -race -covermode=atomic -count=1 .
showcoverage: test
	go tool cover -html=coverage.out
test:
	go test -v -coverprofile coverage.out -covermode=count -count=1 .
vet:
	go vet .
