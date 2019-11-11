# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
GO := go
GOLINT := golint -set_exit_status
GOTEST := $(GO) test -v -coverprofile coverage.out -covermode=count -count=1
PACKAGE_NAMES := $(shell git grep -E -n --no-color -h '^package [a-z0-9]+$$' -- '*.go' ':!vendor/' ':!tools/' | cut -d ':' -f 2 | sed 's/package //g' | sed 's/main/autograph/g' | sort | uniq) monitor
PACKAGE_PATHS := $(subst go.mozilla.org/autograph/signer/autograph,go.mozilla.org/autograph,$(subst go.mozilla.org/autograph/signer/monitor,go.mozilla.org/autograph/tools/autograph-monitor,$(subst go.mozilla.org/autograph/signer/signer,go.mozilla.org/autograph/signer,$(subst go.mozilla.org/autograph/signer/formats,go.mozilla.org/autograph/formats,$(subst go.mozilla.org/autograph/signer/database,go.mozilla.org/autograph/database,$(addprefix go.mozilla.org/autograph/signer/,$(PACKAGE_NAMES)))))))
TEST_TARGETS := $(addprefix test,$(PACKAGE_NAMES))

all: generate test vet lint install

install-golint:
	$(GO) get golang.org/x/lint/golint

install-cover:
	$(GO) get golang.org/x/tools/cmd/cover

install-goveralls:
	$(GO) get github.com/mattn/goveralls

install-migrate:
	$(GO) get -tags 'postgres' -u github.com/golang-migrate/migrate/v4/cmd/migrate/

install-staticcheck:
	$(GO) get honnef.co/go/tools/cmd/staticcheck

install-dev-deps: install-golint install-cover install-goveralls

install:
	$(GO) install go.mozilla.org/autograph

database/schema.sql:
	cat $(shell ls -1 database/migrations/*.up.sql) > database/schema.sql

tools/softhsm/auths.sql:
	$(GO) run go.mozilla.org/autograph -auth-to-sql -c tools/softhsm/autograph.softhsm.yaml -l error > tools/softhsm/auths.sql

vendor:
	go mod vendor

tag: all
	git tag -s $(TAGVER) -a -m "$(TAGMSG)"

lint:
	test 0 -eq $(shell $(GOLINT) $(PACKAGE_PATHS) | tee /tmp/autograph-golint.txt | grep -v 'and that stutters' | wc -l)

# refs: https://github.com/mozilla-services/autograph/issues/247
check-no-crypto11-in-signers:
	test 0 -eq $(shell grep -Ri crypto11 signer/*/ | tee /tmp/autograph-crypto11-check.txt | wc -l)

check-database-sql-files-up-to-date: database/schema.sql tools/softhsm/auths.sql
	test 0 -eq $(shell git diff database/schema.sql | wc -l)
	test 0 -eq $(shell git diff tools/softhsm/auths.sql | wc -l)

show-lint:
	cat /tmp/autograph-golint.txt /tmp/autograph-crypto11-check.txt
	rm -f /tmp/autograph-golint.txt /tmp/autograph-crypto11-check.txt

vet:
	go vet $(PACKAGE_PATHS)

fmt-diff:
	gofmt -d *.go database/ signer/ tools/autograph-client/ $(shell ls tools/autograph-monitor/*.go) tools/softhsm/ tools/hawk-token-maker/ tools/make-hsm-ee/ tools/makecsr/ tools/genpki/

fmt-fix:
	go fmt $(PACKAGE_PATHS)
	gofmt -w tools/autograph-client/ $(shell ls tools/autograph-monitor/*.go) tools/softhsm/ tools/hawk-token-maker/ tools/make-hsm-ee/ tools/makecsr/ tools/genpki/

# for test* and showcoverage* targets include known package names for
# autocompletion but fall through to generic implementation

# non-signer package paths
testautograph: PACKAGE_PATH = go.mozilla.org/autograph
testdatabase: PACKAGE_PATH = go.mozilla.org/autograph/database
testformats:  PACKAGE_PATH = go.mozilla.org/autograph/formats
testmonitor: PACKAGE_PATH = go.mozilla.org/autograph/tools/autograph-monitor
testsigner: PACKAGE_PATH = go.mozilla.org/autograph/signer

testapk:
testcontentsignature:
testcontentsignaturepki:
testgenericrsa:
testgpg2:
testmar:
testpgp:
testrsapss:
testxpi:
# default vars for test* targets https://www.gnu.org/software/make/manual/html_node/Pattern_002dspecific.html#Pattern_002dspecific
test%: PACKAGE_NAME = $(subst test,,$@)
test%: PACKAGE_PATH = $(addprefix go.mozilla.org/autograph/signer/,$(subst test,,$@))
test%: PACKAGE_TEST_OUTPUT_DIR = $(subst test,testprofiles/,$@)
test%:
	mkdir -p $(PACKAGE_TEST_OUTPUT_DIR)
	$(GOTEST) -outputdir "testprofiles/$(PACKAGE_NAME)" $(PACKAGE_PATH)
ifeq ($(RACE_TEST),1)
	$(GO) test -v -race $(PACKAGE_PATH)
endif
ifeq ($(STATIC_CHECK),1)
	$(GO) staticcheck $(PACKAGE_PATH)
endif

# helper command for auth tests
truncate-auth-tables:
	docker-compose exec -u postgres db /bin/bash -lc 'psql autograph -c "TRUNCATE authorizations, signers, hawk_credentials;"'

benchmarkxpi:
benchmark%: PACKAGE_NAME = $(subst benchmark,,$@)
benchmark%: PACKAGE_PATH = $(addprefix go.mozilla.org/autograph/signer/,$(subst benchmark,,$@))
benchmark%: PACKAGE_TEST_OUTPUT_DIR = $(subst benchmark,testprofiles/,$@)
benchmark%:
	mkdir -p $(PACKAGE_TEST_OUTPUT_DIR)
	$(GO) test -run=XXX -benchtime=15s -bench=. -v -cpuprofile "testprofiles/$(PACKAGE_NAME)/cpu.out" $(PACKAGE_PATH)

showbenchmarkxpi:
showbenchmark%: PACKAGE_NAME = $(subst showbenchmark,,$@)
showbenchmark%:
	go tool pprof -web "testprofiles/$(PACKAGE_NAME)/cpu.out"

showcoverageautograph:
showcoveragedatabase:
showcoverageformats:
showcoveragemonitor:
showcoveragesigner:

showcoverageapk:
showcoveragecontentsignature:
showcoveragecontentsignaturepki:
showcoveragegenericrsa:
showcoveragegpg2:
showcoveragemar:
showcoveragepgp:
showcoveragersapss:
showcoveragexpi:

showcoverage%: PACKAGE_NAME = $(subst showcoverage,,$@)
showcoverage%: PACKAGE_TEST_OUTPUT_DIR = $(subst showcoverage,testprofiles/,$@)
showcoverage%:
	make $(subst showcoverage,test,$@)
	$(GO) tool cover -html=$(PACKAGE_TEST_OUTPUT_DIR)/coverage.out -o coverage.html
	python -m webbrowser -t coverage.html

test: $(TEST_TARGETS)
	echo 'mode: count' > coverage.out
	grep -v mode $(shell find testprofiles/ -name coverage.out) | cut -d ':' -f 2,3 >> coverage.out

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

.SUFFIXES:            # Delete the default suffixes
.PHONY: all dummy-statsd test generate vendor integration-test check-no-crypto11-in-signers database/schema.sql tools/softhsm/auths.sql check-database-sql-files-up-to-date truncate-auth-tables
