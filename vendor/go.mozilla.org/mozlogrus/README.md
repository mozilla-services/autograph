# mozlogrus [![GoDoc](https://godoc.org/go.mozilla.org/mozlogrus?status.svg)](https://godoc.org/go.mozilla.org/mozlogrus)
A logging library which conforms to [Mozilla's logging standard](https://wiki.mozilla.org/Firefox/Services/Logging) for [logrus](https://github.com/Sirupsen/logrus).

## Installation

`go get go.mozilla.org/mozlogrus`

## Example

### Basic Usage
```go
package main

import (
	log "github.com/Sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
)

func init() {
	mozlogrus.Enable("ApplicationName")
}

func main() {
	log.WithFields(log.Fields{
		"animal": "walrus",
		"size":   10,
	}).Info("A group of walrus emerges from the ocean")
}
```

```json
$ go run mozlogrus.go | jq
{
  "Timestamp": 1487349663973687600,
  "Time": "2017-02-17T16:41:03Z",
  "Type": "app.log",
  "Logger": "ApplicationName",
  "Hostname": "gator3",
  "EnvVersion": "2.0",
  "Pid": 18061,
  "Severity": 4,
  "Fields": {
    "animal": "walrus",
    "msg": "A group of walrus emerges from the ocean",
    "size": 10
  }
}
```

### Custom Log Types

```go
func init() {
    mozlogrus.EnableFormatter(&mozlogrus.MozLogFormatter{
        LoggerName: "ApplicationName",
        Type: "udp datagram",
    })
}
```
