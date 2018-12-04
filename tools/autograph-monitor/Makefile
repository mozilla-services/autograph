GO := GO111MODULE=on go

build-binary:
	$(GO) build -mod=vendor -o autograph-monitor *.go
build: build-binary
	zip -r autograph-monitor.zip autograph-monitor monitor.autograph.yaml
test:
	$(GO) test -mod=vendor go.mozilla.org/autograph/tools/autograph-monitor
vendor:
	$(GO) mod vendor
	git add vendor/
lint:
	golint *.go
vet:
	$(GO) vet *.go
clean:
	rm autograph-monitor autograph-monitor.zip
.PHONY: vendor clean build build-binary
