# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# The GOPATH isn't always on the path.
GOPATH := $(shell go env GOPATH)

# If you bump this version for golangci-lint, also check if the version of the
# golangci-lint GitHub Action needs to be bumped in .github/workflows.
GOLANGCI_LINT_VERSION := v1.60.1

all: generate test vet lint staticcheck install

# update the vendored version of the wait-for-it.sh script
install-wait-for-it:
	curl -o bin/wait-for-it.sh https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh
	sha256sum -c bin/wait-for-it.sh.sha256
	chmod +x bin/wait-for-it.sh

install-golangci-lint:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

install-goveralls:
	go install github.com/mattn/goveralls@v0.0.11

install-go-mod-upgrade:
	go get github.com/oligot/go-mod-upgrade

install-dev-deps: install-golangci-lint install-goveralls install-go-mod-upgrade

install:
	go install github.com/mozilla-services/autograph

vendor:
	go-mod-upgrade

tag: all
	git tag -s $(TAGVER) -a -m "$(TAGMSG)"

lint:
	golangci-lint run

vet:
	go vet ./...

fmt-diff:
	gofmt -d *.go database/ signer/ tools/autograph-client/ tools/autograph-monitor tools/softhsm/ tools/hawk-token-maker/ tools/make-hsm-ee/ tools/makecsr/ tools/genpki/

fmt-fix:
	go fmt ./...
	gofmt -w tools/autograph-client/ tools/softhsm/ tools/hawk-token-maker/ tools/make-hsm-ee/ tools/makecsr/ tools/genpki/

benchmarkxpi:
	go test -run=XXX -benchtime=15s -bench=. -v -cpuprofile cpu.out github.com/mozilla-services/autograph/signer/xpi ;\

showbenchmarkxpi:
	go tool pprof -web cpu.out

test:
	go test -v -race -coverprofile coverage.out -covermode=atomic -count=1 ./...

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
# monitor -> monitor,monitor-hsm
# app-hsm -> monitor-hsm(app-hsm writes chains and updated config to shared /tmp volume)
#
build: generate
	DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 docker compose build --no-cache --parallel app db
	DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 docker compose build --no-cache --parallel app-hsm monitor
	DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 docker compose build --no-cache --parallel monitor monitor-hsm

# TODO(AUT-287): port this to the Docker compose integration tests
integration-test:
	./bin/run_integration_tests.sh

dummy-statsd:
	nc -kluvw 0 localhost 8125

.SUFFIXES:            # Delete the default suffixes
.PHONY: all dummy-statsd test generate vendor integration-test check-no-crypto11-in-signers test-in-docker
