build:
	go build -o autograph-monitor *.go
	zip -r autograph-monitor.zip autograph-monitor
test:
	go test go.mozilla.org/autograph/tools/autograph-monitor
lint:
	golint *.go
vet:
	go vet *.go
clean:
	rm autograph-monitor autograph-monitor.zip
.PHONY: vendor clean build
