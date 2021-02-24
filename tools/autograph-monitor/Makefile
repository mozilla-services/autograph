build:
	go build -o autograph-monitor *.go
	zip -r autograph-monitor.zip autograph-monitor
test:
	go test -v -coverprofile monitor-coverage.out -covermode=count -count=1 github.com/mozilla-services/autograph/tools/autograph-monitor
lint:
	golint *.go
vet:
	go vet *.go
clean:
	rm autograph-monitor autograph-monitor.zip
vendor:
	go-mod-upgrade
.PHONY: vendor clean build
