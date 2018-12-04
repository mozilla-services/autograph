GO := GO111MODULE=on go

build:
	$(GO) build -o autograph-monitor *.go
	zip -r autograph-monitor.zip autograph-monitor monitor.autograph.yaml
test:
	$(GO) test go.mozilla.org/autograph/tools/autograph-monitor
vendor:
	$(GO) get -u
lint:
	golint *.go
vet:
	$(GO) vet *.go
clean:
	rm autograph-monitor autograph-monitor.zip
.PHONY: vendor clean build
