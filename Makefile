# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
PACKAGE_NAMES := $(shell go list go.mozilla.org/autograph/...|grep -v tools | sed -e :a -e '$!N; s/\n/ /; ta')

all: generate test vet lint install

# update the vendored version of the wait-for-it.sh script
install-wait-for-it:
	curl -o bin/wait-for-it.sh https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh
	chmod +x bin/wait-for-it.sh

install-golint:
	go get -u golang.org/x/lint/golint

install-cover:
	go get -u golang.org/x/tools/cmd/cover

install-goveralls:
	go get -u github.com/mattn/goveralls

install-staticcheck:
	go get -u honnef.co/go/tools/cmd/staticcheck

install-go-mod-upgrade:
	go get -u github.com/oligot/go-mod-upgrade

install-dev-deps: install-golint install-cover install-goveralls install-go-mod-upgrade

install:
	go install go.mozilla.org/autograph

vendor:
	go-mod-upgrade

tag: all
	git tag -s $(TAGVER) -a -m "$(TAGMSG)"

lint:
	golint $(PACKAGE_NAMES) | tee /tmp/autograph-golint.txt
	test 0 -eq $(shell cat /tmp/autograph-golint.txt | grep -Pv 'stutters|suggestions' | wc -l)

# refs: https://github.com/mozilla-services/autograph/issues/247
check-no-crypto11-in-signers:
	test 0 -eq $(shell grep -Ri crypto11 signer/*/ | tee /tmp/autograph-crypto11-check.txt | wc -l)

show-lint:
	cat /tmp/autograph-golint.txt /tmp/autograph-crypto11-check.txt
	rm -f /tmp/autograph-golint.txt /tmp/autograph-crypto11-check.txt

vet:
	go vet $(PACKAGE_NAMES)

fmt-diff:
	gofmt -d *.go database/ signer/ tools/autograph-client/ $(shell ls tools/autograph-monitor/*.go) tools/softhsm/ tools/hawk-token-maker/ tools/make-hsm-ee/ tools/makecsr/ tools/genpki/

fmt-fix:
	go fmt $(PACKAGE_NAMES)
	gofmt -w tools/autograph-client/ $(shell ls tools/autograph-monitor/*.go) tools/softhsm/ tools/hawk-token-maker/ tools/make-hsm-ee/ tools/makecsr/ tools/genpki/

benchmarkxpi:
	go test -run=XXX -benchtime=15s -bench=. -v -cpuprofile cpu.out go.mozilla.org/autograph/signer/xpi ;\

showbenchmarkxpi:
	go tool pprof -web cpu.out

race:
	go test -v -race $(PACKAGE_NAMES)

staticcheck:
	staticcheck $(PACKAGE_NAMES)

test:
	go test -v -coverprofile coverage.out -covermode=count -count=1 $(PACKAGE_NAMES)

showcoverage: test
	go tool cover -html=coverage.out

generate:
	go generate

build: generate
	docker-compose build --no-cache app app-hsm monitor monitor-hsm

integration-test:
	./bin/run_integration_tests.sh

dummy-statsd:
	nc -kluvw 0 localhost 8125

.SUFFIXES:            # Delete the default suffixes
.PHONY: all dummy-statsd test generate vendor integration-test check-no-crypto11-in-signers
