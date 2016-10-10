build:
	chmod +x monitor.py
	go build -o autograph-monitor monitor.go
	zip -r autograph-monitor.zip monitor.py autograph-monitor monitor.autograph.yaml
vendor:
	govend -u
clean:
	rm autograph-monitor autograph-monitor.zip

