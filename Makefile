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
	$(GO) test -covermode=count -coverprofile=coverage_autograph.out go.mozilla.org/autograph

testsigner:
	$(GO) test -covermode=count -coverprofile=coverage_signer.out go.mozilla.org/autograph/signer

test: testautograph testsigner
	#$(GO) test -covermode=count -coverprofile=coverage.out go.mozilla.org/autograph/signer/contentsignature
	#$(GO) test -covermode=count -coverprofile=coverage.out go.mozilla.org/autograph/signer/xpi

showcoverageautograph: testautograph
	$(GO) tool cover -html=coverage_autograph.out

showcoveragesigner: testsigner
	$(GO) tool cover -html=coverage_signer.out

showcoverage: showcoverageautograph showcoveragesigner

generate:
	$(GO) generate

.PHONY: all test generate vendor
