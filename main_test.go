// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/mozilla-services/yaml"

	log "github.com/sirupsen/logrus"
)

// read a signerConfig from a local file
func (c *signerConfig) loadFromFile(path string) error {
	var (
		data []byte
		err  error
	)
	data, err = os.ReadFile(path)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(data, &c)
	if err != nil {
		return err
	}
	return nil
}

func newTestAutographer(t *testing.T) (*autographer, serviceConfig, signerConfig) {
	var serviceConf serviceConfig
	var signerConf signerConfig

	// load the service and signer config
	err := serviceConf.loadFromFile("autograph-service.yaml")
	if err != nil {
		log.Fatal(err)
	}
	err = signerConf.loadFromFile("autograph-signer.yaml")
	if err != nil {
		log.Fatal(err)
	}
	ag := newAutographer(1)
	err = ag.addSigners(signerConf.Signers)
	if err != nil {
		log.Fatal(err)
	}
	err = ag.addAuthorizations(signerConf.Authorizations)
	if err != nil {
		log.Fatal(err)
	}
	err = ag.addMonitoring(serviceConf.Monitoring)
	if err != nil {
		log.Fatal(err)
	}
	if serviceConf.HawkTimestampValidity != "" {
		ag.hawkMaxTimestampSkew, err = time.ParseDuration(serviceConf.HawkTimestampValidity)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		ag.hawkMaxTimestampSkew = time.Minute
	}

	t.Cleanup(func() {
		close(ag.exit)
	})

	return ag, serviceConf, signerConf
}

func TestServiceConfigLoad(t *testing.T) {
	testcases := []struct {
		name string
		pass bool
		data []byte
	}{
		{"simple service", true, []byte(`
server:
    listen: "localhost:8888"
    noncecachesize: 64

heartbeat:
    hsmchecktimeout: 100ms
    dbchecktimeout: 150ms

monitoring:
    key: qowidhqowidhqoihdqodwh
`)},
		{"missing heartbeat", false, []byte(`
server:
    listen: "localhost:8000"
    noncecachesize: 64
`)},

		{"bogus yaml", false, []byte(`{{{{{{{`)},
		{"yaml with tabs", false, []byte(`
server:
	listen: "localhost:8000"
	noncecachesize: 64

heartbeat:
    hsmchecktimeout: 100ms
    dbchecktimeout: 150ms
    hsmtestsignerid: signeridhere
`)},
	}
	for i, testcase := range testcases {
		var conf serviceConfig
		// write conf file to /tmp and read it back
		fd, err := os.CreateTemp("", "testserviceconf")
		if err != nil {
			t.Fatal(err)
		}
		fi, err := fd.Stat()
		if err != nil {
			t.Fatal(err)
		}
		filename := fmt.Sprintf("%s/%s", os.TempDir(), fi.Name())
		_, err = fd.Write(testcase.data)
		if err != nil {
			t.Fatal(err)
		}
		fd.Close()
		err = conf.loadFromFile(filename)
		if err != nil && testcase.pass {
			t.Fatalf("testcase %d %q failed and should have passed: %v",
				i, testcase.name, err)
		}
		if err == nil && !testcase.pass {
			t.Fatalf("testcase %d %q passed and should have failed", i, testcase.name)
		}
		os.Remove(filename)
	}
}

func TestDefaultPortUnset(t *testing.T) {
	expected := ""
	_, port, _ := parseArgs([]string{})
	if port != expected {
		t.Errorf("expected listen %s got %s", expected, port)
	}
}

func TestPortOverride(t *testing.T) {
	expected := "8080"
	_, port, _ := parseArgs([]string{"-p", "8080"})
	if port != expected {
		t.Errorf("expected listen %s got %s", expected, port)
	}
}
