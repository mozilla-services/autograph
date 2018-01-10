build:
	chmod +x monitor.py
	go build -o autograph-monitor *.go
	zip -r autograph-monitor.zip monitor.py autograph-monitor monitor.autograph.yaml
test:
	go test go.mozilla.org/autograph/tools/autograph-monitor
vendor:
	govend -u
lint:
	golint *.go
vet:
	go vet *.go
clean:
	rm autograph-monitor autograph-monitor.zip
.PHONY: vendor clean build
