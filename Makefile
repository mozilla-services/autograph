# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
PACKAGE_NAMES := github.com/mozilla-services/autograph github.com/mozilla-services/autograph/database github.com/mozilla-services/autograph/formats github.com/mozilla-services/autograph/signer github.com/mozilla-services/autograph/signer/apk2 github.com/mozilla-services/autograph/signer/contentsignature github.com/mozilla-services/autograph/signer/contentsignaturepki github.com/mozilla-services/autograph/signer/genericrsa github.com/mozilla-services/autograph/signer/gpg2 github.com/mozilla-services/autograph/signer/mar github.com/mozilla-services/autograph/signer/xpi github.com/mozilla-services/autograph/verifier/contentsignature

all: generate test vet staticcheck install

# update the vendored version of the wait-for-it.sh script
install-wait-for-it:
	curl -o bin/wait-for-it.sh https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh
	sha256sum -c bin/wait-for-it.sh.sha256
	chmod +x bin/wait-for-it.sh

install-cover:
	go get -u golang.org/x/tools/cmd/cover

install-goveralls:
	go get -u github.com/mattn/goveralls

install-staticcheck:
	go get -u honnef.co/go/tools/cmd/staticcheck

install-go-mod-upgrade:
	go get -u github.com/oligot/go-mod-upgrade

install-dev-deps: install-staticcheck install-cover install-goveralls install-go-mod-upgrade

install:
	go install github.com/mozilla-services/autograph

vendor:
	go-mod-upgrade

tag: all
	git tag -s $(TAGVER) -a -m "$(TAGMSG)"

# refs: https://github.com/mozilla-services/autograph/issues/247
check-no-crypto11-in-signers:
	test 0 -eq $(shell grep -Ri crypto11 signer/*/ | tee /tmp/autograph-crypto11-check.txt | wc -l)

show-lint:
	cat /tmp/autograph-staticcheck.txt /tmp/autograph-crypto11-check.txt
	rm -f /tmp/autograph-staticcheck.txt /tmp/autograph-crypto11-check.txt

vet:
	go vet $(PACKAGE_NAMES)

fmt-diff:
	gofmt -d *.go database/ signer/ tools/autograph-client/ $(shell ls tools/autograph-monitor/*.go) tools/softhsm/ tools/hawk-token-maker/ tools/make-hsm-ee/ tools/makecsr/ tools/genpki/

fmt-fix:
	go fmt $(PACKAGE_NAMES)
	gofmt -w tools/autograph-client/ $(shell ls tools/autograph-monitor/*.go) tools/softhsm/ tools/hawk-token-maker/ tools/make-hsm-ee/ tools/makecsr/ tools/genpki/

benchmarkxpi:
	go test -run=XXX -benchtime=15s -bench=. -v -cpuprofile cpu.out github.com/mozilla-services/autograph/signer/xpi ;\

showbenchmarkxpi:
	go tool pprof -web cpu.out

race:
	go test -race -covermode=atomic -count=1 $(PACKAGE_NAMES)

staticcheck:
	staticcheck -go 1.15 $(PACKAGE_NAMES) | tee /tmp/autograph-staticcheck.txt

test:
	go test -v -coverprofile coverage.out -covermode=count -count=1 $(PACKAGE_NAMES)

showcoverage: test
	go tool cover -html=coverage.out

generate:
	go generate

# image build order:
#
# app -> {app-hsm,monitor}
# monitor -> monitor-lambda-emulator,monitor-hsm-lambda-emulator
# app-hsm -> monitor-hsm-lambda-emulator (app-hsm writes chains and updated config to shared /tmp volume)
#
build: generate
	DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 docker-compose build --no-cache --parallel app db
	DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 docker-compose build --no-cache --parallel app-hsm monitor
	DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 docker-compose build --no-cache --parallel monitor-lambda-emulator monitor-hsm-lambda-emulator

integration-test:
	./bin/run_integration_tests.sh

dummy-statsd:
	nc -kluvw 0 localhost 8125

.SUFFIXES:            # Delete the default suffixes
.PHONY: all dummy-statsd test generate vendor integration-test check-no-crypto11-in-signers
