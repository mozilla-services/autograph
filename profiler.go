// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"net/http/pprof"
	"os"
	"runtime"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// setRuntimeConfig sets runtime config options from env vars
func setRuntimeConfig() (err error) {
	var (
		// BlockProfileRate is the fraction of goroutine blocking
		// events that are reported in the blocking profile. The
		// profiler aims to sample an average of one blocking event
		// per rate nanoseconds spent blocked.
		//
		// To include every blocking event in the profile, pass rate = 1. To turn off profiling entirely, pass rate <= 0.
		//
		// https://golang.org/pkg/runtime/#SetBlockProfileRate
		blockProfileRate int = 0

		// mutexProfileFraction is the rate of mutex contention events
		// that are reported in the mutex profile. On average 1/rate
		// events are reported. The previous rate is returned.
		//
		// To turn off profiling entirely, pass rate 0. To just read
		// the current rate, pass rate < 0. (For n>1 the details of
		// sampling may change.)
		//
		// https://golang.org/pkg/runtime/#SetMutexProfileFraction
		mutexProfileFraction int = 0
	)
	val, ok := os.LookupEnv("BLOCK_PROFILE_RATE")
	if ok {
		blockProfileRate, err = strconv.Atoi(val)
		if err != nil {
			return errors.Wrap(err, "failed to parse BLOCK_PROFILE_RATE as int")
		}
		runtime.SetBlockProfileRate(blockProfileRate)
		log.Infof("SetBlockProfileRate to %d", blockProfileRate)
	} else {
		log.Infof("Did not SetBlockProfileRate. BLOCK_PROFILE_RATE is not set.")
	}
	val, ok = os.LookupEnv("MUTEX_PROFILE_FRACTION")
	if ok {
		mutexProfileFraction, err = strconv.Atoi(val)
		if err != nil {
			return errors.Wrap(err, "failed to parse MUTEX_PROFILE_FRACTION as int")
		}
		runtime.SetMutexProfileFraction(mutexProfileFraction)
		log.Infof("SetMutexProfileFraction to %d", mutexProfileFraction)
	} else {
		log.Infof("Did not SetMutexProfileFraction. MUTEX_PROFILE_FRACTION is not set.")
	}
	return nil
}

// addProfilerHandlers adds debug pprof handlers
func addProfilerHandlers(router *mux.Router) {
	router.HandleFunc("/debug/pprof/", pprof.Index)
	router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	router.HandleFunc("/debug/pprof/profile", pprof.Profile)
	router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	router.HandleFunc("/debug/pprof/trace", pprof.Trace)
}
