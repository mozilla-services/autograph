# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
PACKAGE_NAMES := github.com/mozilla-services/autograph github.com/mozilla-services/autograph/database github.com/mozilla-services/autograph/formats github.com/mozilla-services/autograph/signer github.com/mozilla-services/autograph/signer/apk2 github.com/mozilla-services/autograph/signer/contentsignature github.com/mozilla-services/autograph/signer/contentsignaturepki github.com/mozilla-services/autograph/signer/genericrsa github.com/mozilla-services/autograph/signer/gpg2 github.com/mozilla-services/autograph/signer/mar github.com/mozilla-services/autograph/signer/xpi github.com/mozilla-services/autograph/verifier/contentsignature

all: generate test vet lint staticcheck install

# update the vendored version of the wait-for-it.sh script
install-wait-for-it:
	curl -o bin/wait-for-it.sh https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh
	sha256sum -c bin/wait-for-it.sh.sha256
	chmod +x bin/wait-for-it.sh

install-golint:
	go get golang.org/x/lint/golint

install-cover:
	go get golang.org/x/tools/cmd/cover

install-goveralls:
	go get github.com/mattn/goveralls

install-staticcheck:
	go get honnef.co/go/tools/cmd/staticcheck

install-go-mod-upgrade:
	go get github.com/oligot/go-mod-upgrade

install-dev-deps: install-golint install-staticcheck install-cover install-goveralls install-go-mod-upgrade

install:
	go install github.com/mozilla-services/autograph

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

show-lints:
	-cat /tmp/autograph-golint.txt /tmp/autograph-crypto11-check.txt /tmp/autograph-staticcheck.txt
	-rm -f /tmp/autograph-golint.txt /tmp/autograph-crypto11-check.txt /tmp/autograph-staticcheck.txt

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
	staticcheck -go 1.16 $(PACKAGE_NAMES) | tee /tmp/autograph-staticcheck.txt
	# ignore errors in pkgs
	# ignore SA1019 for DSA being deprecated refs: GH #667
	test 0 -eq $(shell cat /tmp/autograph-staticcheck.txt | grep -Pv '^/go/pkg/mod/|SA1019' | wc -l)

test:
	go test -v -coverprofile coverage.out -covermode=count -count=1 $(PACKAGE_NAMES)

test-in-docker:
	$(SHELL) -c " \
		docker compose up 2>&1 | tee test-in-docker.log \
		| (grep --silent 'autograph-unit-test exited with code' && docker compose down; \
		grep 'autograph-unit-test' test-in-docker.log >unit-test.log ; \
		tail -2 unit-test.log)"


showcoverage: test
	go tool cover -html=coverage.out

generate:
	go generate

gpg-test-clean:
	rm -rf /tmp/autograph_gpg2*
	killall gpg-agent

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
.PHONY: all dummy-statsd test generate vendor integration-test check-no-crypto11-in-signers test-in-docker
