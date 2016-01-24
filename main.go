// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

//go:generate ./version.sh

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/mozilla-services/go-mozlog"

	"gopkg.in/yaml.v2"
)

func init() {
	// initialize the logger
	mozlog.Logger.LoggerName = "Autograph"
}

func main() {
	var (
		ag          *autographer
		conf        configuration
		cfgFile     string
		showVersion bool
		err         error
	)
	flag.StringVar(&cfgFile, "c", "/etc/autograph/autograph.yaml", "Path to configuration file")
	flag.BoolVar(&showVersion, "V", false, "Show build version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	err = conf.loadFromFile(cfgFile)
	if err != nil {
		log.Fatal(err)
	}

	// initialize signers from the configuration
	// and store them into the autographer handler
	ag = new(autographer)
	for _, sgc := range conf.Signers {
		sgc.init()
		ag.addSigner(sgc)
	}
	go ag.removeNonces()

	// start serving
	mux := http.NewServeMux()
	mux.HandleFunc("/__heartbeat__", ag.handleHeartbeat)
	mux.HandleFunc("/signature", ag.handleSignature)
	server := &http.Server{
		Addr:    conf.Server.Listen,
		Handler: mux,
	}
	err = server.ListenAndServe()
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

func (c *configuration) loadFromFile(path string) error {
	fd, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(fd, &c)
	if err != nil {
		return err
	}
	return nil
}
