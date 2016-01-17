// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/mozilla-services/go-mozlog"

	"gopkg.in/yaml.v2"
)

func init() {
	// initialize the logger
	mozlog.Logger.LoggerName = "Autograph"
}

func main() {
	var (
		ag      *autographer
		conf    configuration
		cfgFile string
	)
	flag.StringVar(&cfgFile, "c", "autograph.yaml", "Path to configuration file")
	flag.Parse()

	conf.loadFromFile(cfgFile)

	// initialize signers from the configuration
	// and store them into the autographer handler
	ag = new(autographer)
	for _, sgc := range conf.Signers {
		sgc.init()
		ag.addSigner(sgc)
	}

	// start serving
	mux := http.NewServeMux()
	mux.HandleFunc("/__heartbeat__", ag.heartbeat)
	mux.HandleFunc("/signature", ag.signature)
	server := &http.Server{
		Addr:    conf.Server.Listen,
		Handler: mux,
	}
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

// configuration loads a yaml file that contains the configuration of Autograph
type configuration struct {
	Server struct {
		Listen string
	}
	Signers []Signer
}

func (c *configuration) loadFromFile(path string) {
	fd, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(fd, &c)
	if err != nil {
		log.Fatal(err)
	}
}
