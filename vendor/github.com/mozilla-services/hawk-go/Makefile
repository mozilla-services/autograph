GO = GO15VENDOREXPERIMENT=1 go
GOLINT = golint

all: test vet generate

tag: all
	git tag -s $(TAGVER) -a -m "$(TAGMSG)"

lint:
	$(GOLINT) github.com/mozilla-services/hawk-go

vet:
	$(GO) vet github.com/mozilla-services/hawk-go

test:
	$(GO) test -covermode=count -coverprofile=coverage.out github.com/mozilla-services/hawk-go

showcoverage: test
	$(GO) tool cover -html=coverage.out

generate:
	$(GO) generate

.PHONY: all test generate

