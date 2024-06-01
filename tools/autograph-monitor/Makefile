# The GOPATH isn't always on the path.
GOPATH := $(shell go env GOPATH)

build:
	go build -o autograph-monitor *.go
	zip -r autograph-monitor.zip autograph-monitor
build-image:
	docker build -t autograph-monitor:latest .
doc:
	go doc -all .
doc-http:
	godoc -http=:8080
test:
	go test -coverprofile monitor-coverage.out -covermode=count -count=1 github.com/mozilla-services/autograph/tools/autograph-monitor
test-cover-report:
	go tool cover -func=monitor-coverage.out
test-cover-report-html:
	go tool cover -html=monitor-coverage.out
race:
	go test -race -covermode=atomic -count=1 .
lint:
	$(GOPATH)/bin/golint *.go
staticcheck:
	$(GOPATH)/bin/staticcheck *.go
vet:
	go vet *.go
clean:
	rm autograph-monitor autograph-monitor.zip
vendor:
	go-mod-upgrade
.PHONY: vendor clean build
