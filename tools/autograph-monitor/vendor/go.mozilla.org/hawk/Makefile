GO = GO15VENDOREXPERIMENT=1 go
GOLINT = golint
PROJECT = go.mozilla.org/hawk

all: test vet generate

tag: all
	git tag -s $(TAGVER) -a -m "$(TAGMSG)"

lint:
	$(GOLINT) $(PROJECT)

vet:
	$(GO) vet $(PROJECT)

test:
	$(GO) test -covermode=count -coverprofile=coverage.out $(PROJECT)

showcoverage: test
	$(GO) tool cover -html=coverage.out

generate:
	$(GO) generate

.PHONY: all test generate

