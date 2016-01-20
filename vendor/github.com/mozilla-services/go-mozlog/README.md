# go-mozlog [![GoDoc](https://godoc.org/github.com/mozilla-services/go-mozlog?status.svg)](https://godoc.org/github.com/mozilla-services/go-mozlog) [![Build Status](https://travis-ci.org/mozilla-services/go-mozlog.svg?branch=master)](https://travis-ci.org/mozilla-services/go-mozlog)
A logging library which conforms to Mozilla's logging standard.

## Example Usage
```
import "github.com/mozilla-services/go-mozlog"

func init() {
    mozlog.Logger.LoggerName = "ApplicationName"
}
```
