# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
GO := go
GOLINT := golint -set_exit_status
GOTEST := $(GO) test -v -covermode=count -count=1

PACKAGES := go.mozilla.org/autograph \
go.mozilla.org/autograph/database \
go.mozilla.org/autograph/signer \
go.mozilla.org/autograph/formats \
go.mozilla.org/autograph/signer/apk \
go.mozilla.org/autograph/signer/apk2 \
go.mozilla.org/autograph/signer/contentsignature \
go.mozilla.org/autograph/signer/contentsignaturepki \
go.mozilla.org/autograph/signer/mar \
go.mozilla.org/autograph/signer/xpi \
go.mozilla.org/autograph/signer/mar \
go.mozilla.org/autograph/signer/pgp \
go.mozilla.org/autograph/signer/gpg2 \
go.mozilla.org/autograph/signer/genericrsa \
go.mozilla.org/autograph/signer/rsapss

all: generate test vet lint install

install-golint:
	$(GO) get golang.org/x/lint/golint

install-cover:
	$(GO) get golang.org/x/tools/cmd/cover

install-goveralls:
	$(GO) get github.com/mattn/goveralls

install-dev-deps: install-golint install-cover install-goveralls

install:
	$(GO) install go.mozilla.org/autograph

vendor:
	go mod vendor

tag: all
	git tag -s $(TAGVER) -a -m "$(TAGMSG)"

lint:
	test 0 -eq $(shell $(GOLINT) $(PACKAGES) | tee /tmp/autograph-golint.txt | grep -v 'and that stutters' | wc -l)

show-lint:
	cat /tmp/autograph-golint.txt
	rm -f /tmp/autograph-golint.txt

vet:
	go vet $(PACKAGES)

fmt-diff:
	gofmt -d *.go database/ signer/ tools/autograph-client/ $(shell ls tools/autograph-monitor/*.go) tools/softhsm/ tools/hawk-token-maker/ tools/make-hsm-ee/ tools/makecsr/ tools/genpki/

fmt-fix:
	go fmt $(PACKAGES)
	gofmt -w tools/autograph-client/ $(shell ls tools/autograph-monitor/*.go) tools/softhsm/ tools/hawk-token-maker/ tools/make-hsm-ee/ tools/makecsr/ tools/genpki/

testautograph:
	$(GOTEST) -coverprofile=coverage_autograph.out go.mozilla.org/autograph

showcoverageautograph: testautograph
	$(GO) tool cover -html=coverage_autograph.out

testautographdb:
	$(GOTEST) -coverprofile=coverage_db.out go.mozilla.org/autograph/database

showcoverageautographdb: testautographdb
	$(GO) tool cover -html=coverage_db.out

testautographformats:
	$(GOTEST) -coverprofile=coverage_formats.out go.mozilla.org/autograph/formats

showcoverageautographformats: testautographformats
	$(GO) tool cover -html=coverage_formats.out

testsigner:
	$(GOTEST) -coverprofile=coverage_signer.out go.mozilla.org/autograph/signer

showcoveragesigner: testsigner
	$(GO) tool cover -html=coverage_signer.out

testmonitor:
	$(GOTEST) -coverprofile=coverage_monitor.out go.mozilla.org/autograph/tools/autograph-monitor

testcs:
	$(GOTEST) -coverprofile=coverage_cs.out go.mozilla.org/autograph/signer/contentsignature

showcoveragecs: testcs
	$(GO) tool cover -html=coverage_cs.out

testcspki:
	$(GOTEST) -coverprofile=coverage_cspki.out go.mozilla.org/autograph/signer/contentsignaturepki

showcoveragecspki: testcspki
	$(GO) tool cover -html=coverage_cspki.out

testxpi:
	$(GOTEST) -coverprofile=coverage_xpi.out go.mozilla.org/autograph/signer/xpi

showcoveragexpi: testxpi
	$(GO) tool cover -html=coverage_xpi.out

testapk:
	$(GOTEST) -coverprofile=coverage_apk.out go.mozilla.org/autograph/signer/apk

showcoverageapk: testapk
	$(GO) tool cover -html=coverage_apk.out

testapk2:
	$(GOTEST) -coverprofile=coverage_apk2.out go.mozilla.org/autograph/signer/apk2

showcoverageapk2: testapk2
	$(GO) tool cover -html=coverage_apk2.out

testmar:
	$(GOTEST) -coverprofile=coverage_mar.out go.mozilla.org/autograph/signer/mar

showcoveragemar: testmar
	$(GO) tool cover -html=coverage_mar.out

testpgp:
	$(GOTEST) -coverprofile=coverage_pgp.out go.mozilla.org/autograph/signer/pgp

showcoveragepgp: testpgp
	$(GO) tool cover -html=coverage_pgp.out

testgpg2:
	$(GOTEST) -coverprofile=coverage_gpg2.out go.mozilla.org/autograph/signer/gpg2

showcoveragegpg2: testgpg2
	$(GO) tool cover -html=coverage_gpg2.out

testgenericrsa:
	$(GOTEST) -coverprofile=coverage_genericrsa.out go.mozilla.org/autograph/signer/genericrsa

showcoveragegenericrsa: testgenericrsa
	$(GO) tool cover -html=coverage_genericrsa.out

testrsapss:
	$(GOTEST) -coverprofile=coverage_rsapss.out go.mozilla.org/autograph/signer/rsapss

showcoveragersapss: testrsapss
	$(GO) tool cover -html=coverage_rsapss.out

test: testautograph testautographdb testautographformats testsigner testcs testcspki testxpi testapk testapk2 testmar testpgp testgpg2 testgenericrsa testrsapss testmonitor
	echo 'mode: count' > coverage.out
	grep -v mode coverage_*.out | cut -d ':' -f 2,3 >> coverage.out

showcoverage: test
	$(GO) tool cover -html=coverage.out

generate:
	$(GO) generate

build: generate
	docker-compose build app app-hsm monitor monitor-hsm

integration-test:
	./bin/run_integration_tests.sh

dummy-statsd:
	nc -kluvw 0 localhost 8125

.PHONY: all dummy-statsd test generate vendor integration-test
