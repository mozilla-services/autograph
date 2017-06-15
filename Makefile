# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

PROJECT		:= go.mozilla.org/autograph
GO 			:= go

all: generate test vet lint install

install:
	$(GO) install $(PROJECT)

vendor:
	govend -u
	#go get -u github.com/golang/dep/...
	#dep ensure -update

tag: all
	git tag -s $(TAGVER) -a -m "$(TAGMSG)"

lint:
	golint $(PROJECT)

vet:
	$(GO) vet $(PROJECT)

testautograph:
	$(GO) test -v -covermode=count -coverprofile=coverage_autograph.out go.mozilla.org/autograph

showcoverageautograph: testautograph
	$(GO) tool cover -html=coverage_autograph.out

testsigner:
	$(GO) test -v -covermode=count -coverprofile=coverage_signer.out go.mozilla.org/autograph/signer

showcoveragesigner: testsigner
	$(GO) tool cover -html=coverage_signer.out

testcs:
	$(GO) test -v -covermode=count -coverprofile=coverage_cs.out go.mozilla.org/autograph/signer/contentsignature

showcoveragecs: testcs
	$(GO) tool cover -html=coverage_cs.out

testxpi:
	$(GO) test -v -covermode=count -coverprofile=coverage_xpi.out go.mozilla.org/autograph/signer/xpi

showcoveragexpi: testxpi
	$(GO) tool cover -html=coverage_xpi.out

test:
	$(GO) test $(go list ./... | grep -v /vendor/)

showcoverage: testautograph testsigner testcs
	echo 'mode: count' > coverage.out
	grep -v mode coverage_*.out | cut -d ':' -f 2,3 >> coverage.out
	$(GO) tool cover -html=coverage.out

generate:
	$(GO) generate

.PHONY: all test generate vendor
