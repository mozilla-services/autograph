# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
GO := go
GOLINT := golint -set_exit_status

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

build-app-container: generate
	docker-compose build autograph-app

build-monitor-container: build-app-container
	docker-compose build autograph-monitor

build-softhsm-container:
	docker-compose build autograph-app-hsm

test-container:
	docker run --name autograph-dev --rm -u 0 --net host app:build make -C /go/src/go.mozilla.org/autograph test

run-container:
	docker run --name autograph-dev --rm -d --net host app:build

compose:
	docker-compose up --build

vendor:
	govend -u --prune
	#go get -u github.com/golang/dep/...
	#dep ensure -update
	rm -rf vendor/go.mozilla.org/autograph/  # don't vendor ourselves
	git add vendor/

tag: all
	git tag -s $(TAGVER) -a -m "$(TAGMSG)"

lint:
	$(GOLINT) go.mozilla.org/autograph \
		go.mozilla.org/autograph/database \
		go.mozilla.org/autograph/signer \
		go.mozilla.org/autograph/signer/contentsignature \
		go.mozilla.org/autograph/signer/contentsignaturepki \
		go.mozilla.org/autograph/signer/xpi \
		go.mozilla.org/autograph/signer/apk \
		go.mozilla.org/autograph/signer/mar \
		go.mozilla.org/autograph/signer/pgp \
		go.mozilla.org/autograph/signer/gpg2 \
		go.mozilla.org/autograph/signer/rsapss

vet:
	$(GO) vet go.mozilla.org/autograph
	$(GO) vet go.mozilla.org/autograph/database
	$(GO) vet go.mozilla.org/autograph/signer
	$(GO) vet go.mozilla.org/autograph/signer/apk
	$(GO) vet go.mozilla.org/autograph/signer/contentsignature
	$(GO) vet go.mozilla.org/autograph/signer/contentsignaturepki
	$(GO) vet go.mozilla.org/autograph/signer/mar
	$(GO) vet go.mozilla.org/autograph/signer/xpi
	$(GO) vet go.mozilla.org/autograph/signer/apk
	$(GO) vet go.mozilla.org/autograph/signer/mar
	$(GO) vet go.mozilla.org/autograph/signer/pgp
	$(GO) vet go.mozilla.org/autograph/signer/gpg2
	$(GO) vet go.mozilla.org/autograph/signer/rsapss

fmt-diff:
	gofmt -d *.go database/ signer/ tools/autograph-client/ $(shell ls tools/autograph-monitor/*.go) tools/softhsm/ tools/hawk-token-maker/

fmt-fix:
	gofmt -w *.go database/ signer/ tools/autograph-client/ $(shell ls tools/autograph-monitor/*.go) tools/softhsm/ tools/hawk-token-maker/

testautograph:
	$(GO) test -v -covermode=count -coverprofile=coverage_autograph.out go.mozilla.org/autograph

showcoverageautograph: testautograph
	$(GO) tool cover -html=coverage_autograph.out

testautographdb:
	$(GO) test -v -covermode=count -count=1 -coverprofile=coverage_db.out go.mozilla.org/autograph/database

showcoverageautographdb: testautographdb
	$(GO) tool cover -html=coverage_db.out

testsigner:
	$(GO) test -v -covermode=count -coverprofile=coverage_signer.out go.mozilla.org/autograph/signer

showcoveragesigner: testsigner
	$(GO) tool cover -html=coverage_signer.out

testmonitor:
	$(GO) test -v -covermode=count -coverprofile=coverage_monitor.out go.mozilla.org/autograph/tools/autograph-monitor

testcs:
	$(GO) test -v -covermode=count -coverprofile=coverage_cs.out go.mozilla.org/autograph/signer/contentsignature

showcoveragecs: testcs
	$(GO) tool cover -html=coverage_cs.out

testcspki:
	$(GO) test -v -covermode=count -coverprofile=coverage_cspki.out go.mozilla.org/autograph/signer/contentsignaturepki

showcoveragecspki: testcspki
	$(GO) tool cover -html=coverage_cspki.out

testxpi:
	$(GO) test -v -covermode=count -coverprofile=coverage_xpi.out go.mozilla.org/autograph/signer/xpi

showcoveragexpi: testxpi
	$(GO) tool cover -html=coverage_xpi.out

testapk:
	$(GO) test -v -covermode=count -coverprofile=coverage_apk.out go.mozilla.org/autograph/signer/apk

showcoverageapk: testapk
	$(GO) tool cover -html=coverage_apk.out

testmar:
	$(GO) test -v -covermode=count -coverprofile=coverage_mar.out go.mozilla.org/autograph/signer/mar

showcoveragemar: testmar
	$(GO) tool cover -html=coverage_mar.out

testpgp:
	$(GO) test -v -covermode=count -coverprofile=coverage_pgp.out go.mozilla.org/autograph/signer/pgp

showcoveragepgp: testpgp
	$(GO) tool cover -html=coverage_pgp.out

testgpg2:
	$(GO) test -v -covermode=count -coverprofile=coverage_gpg2.out go.mozilla.org/autograph/signer/gpg2

showcoveragegpg2: testgpg2
	$(GO) tool cover -html=coverage_gpg2.out

testrsapss:
	$(GO) test -v -covermode=count -coverprofile=coverage_rsapss.out go.mozilla.org/autograph/signer/rsapss

showcoveragersapss: testrsapss
	$(GO) tool cover -html=coverage_rsapss.out

test: testautograph testautographdb testsigner testcs testcspki testxpi testapk testmar testpgp testgpg2 testrsapss
	echo 'mode: count' > coverage.out
	grep -v mode coverage_*.out | cut -d ':' -f 2,3 >> coverage.out

showcoverage: test
	$(GO) tool cover -html=coverage.out

generate:
	$(GO) generate

dummy-statsd:
	nc -kluvw 0 localhost 8125

.PHONY: all dummy-statsd test generate vendor