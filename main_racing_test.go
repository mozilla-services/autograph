//go:build !race
// +build !race

package main

import (
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestLogLevelParsing(t *testing.T) {
	t.Parallel()

	var (
		debug bool
		fatal bool = false
	)
	_, _, debug = parseArgsAndLoadConfig([]string{"-l", "debug"})
	if !(debug == true && log.GetLevel() == log.DebugLevel) {
		t.Errorf("failed to set debug flag for debug log level")
	}
	_, _, debug = parseArgsAndLoadConfig([]string{"-D"})
	if !(debug == true && log.GetLevel() == log.DebugLevel) {
		t.Errorf("failed to set debug log level for debug flag")
	}
	_, _, debug = parseArgsAndLoadConfig([]string{"-l", "error"})
	if !(debug == false && log.GetLevel() == log.ErrorLevel) {
		t.Errorf("failed to set error log level")
	}

	log.StandardLogger().ExitFunc = func(int) { fatal = true }
	_, _, _ = parseArgsAndLoadConfig([]string{"-l", "error", "-D"})
	if fatal != true {
		t.Errorf("did not fail for mismatched log level and debug flag")
	}

	fatal = false
	_, _, _ = parseArgsAndLoadConfig([]string{"-l", "foo"})
	if fatal != true {
		t.Errorf("did not fail for invalid log level")
	}
	log.StandardLogger().ExitFunc = nil
}
