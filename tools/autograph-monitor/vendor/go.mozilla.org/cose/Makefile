

install:
	dep ensure || echo "go dep not found (try https://golang.github.io/dep/docs/installation.html)"

	# dev requirements
	go get -u github.com/stretchr/testify/assert
	go get -u github.com/dvyukov/go-fuzz/...

	mkdir -p test
	cd test && git clone https://github.com/cose-wg/Examples.git cose-wg-examples || true
	cd test && git clone https://github.com/g-k/cose-rust.git || true
	cd test/cose-rust && git checkout test-verify-cli

# sample generated with:
# for file in $(find . -name *.json); do jq '.output.cbor' < $file | tr -d \" | base64 --decode > $(echo $file | sed s/..// | tr '/' '_').cose; done
fuzz:
	mkdir -p workdir/corpus
	cp samples/*.cose workdir/corpus
	go-fuzz-build go.mozilla.org/cose
	go-fuzz -bin=./cose-fuzz.zip -workdir=workdir

lint:
	golint

vet:
	go vet

coverage:
	go test -coverprofile=coverage.out && go tool cover -html=coverage.out

what-todo:
	rg -g '**/*.go' -i TODO

install-golint:
	go get -u golang.org/x/lint/golint

install-godep:
	curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh

goveralls:
	go get -u github.com/mattn/goveralls

smoketest-examples:
	go run example/sign.go
	go run example/verify.go

ci: install-godep install-golint goveralls install coverage lint vet
	goveralls -coverprofile=coverage.out -service=travis-ci -repotoken $(COVERALLS_TOKEN)
