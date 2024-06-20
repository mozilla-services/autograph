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

	log "github.com/sirupsen/logrus"
)

var (
	ag   *autographer
	mo   *monitor
	conf configuration
)

func TestMain(m *testing.M) {
	// load the signers
	err := conf.loadFromFile("autograph.yaml")
	if err != nil {
		log.Fatal(err)
	}
	ag = newAutographer(1)
	err = ag.addSigners(conf.Signers)
	if err != nil {
		log.Fatal(err)
	}
	err = ag.addAuthorizations(conf.Authorizations)
	if err != nil {
		log.Fatal(err)
	}
	err = ag.addMonitoring(conf.Monitoring)
	if err != nil {
		log.Fatal(err)
	}
	if conf.Statsd.Addr != "" {
		err = ag.addStats(conf)
		if err != nil {
			log.Fatal(err)
		}
	}
	if conf.HawkTimestampValidity != "" {
		ag.hawkMaxTimestampSkew, err = time.ParseDuration(conf.HawkTimestampValidity)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		ag.hawkMaxTimestampSkew = time.Minute
	}
	// ok this is lame but the contentsignaturepki signer will upload a file dated
	// at the given second so we don't want anything else to run at the same second
	// otherwise that file may get rewritten. Easiest way to solve it? Sleep.
	time.Sleep(time.Second)

	// Initialize a monitor.
	mo = newMonitor(ag, conf.MonitorInterval)

	// run the tests and exit
	r := m.Run()

	// Shutdown the monitor
	close(ag.exit)

	os.Exit(r)
}

func TestConfigLoad(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name string
		pass bool
		data []byte
	}{
		{"one signer", true, []byte(`
server:
    listen: "localhost:8000"
    noncecachesize: 64

heartbeat:
    hsmchecktimeout: 100ms
    dbchecktimeout: 150ms

signers:
    - id: testsigner1
      privatekey: |
        -----BEGIN EC PRIVATE KEY-----
        MIGkAgEBBDBe7dXZ/epqVkrRWbStmwe2WyTcpWJ5cCbrqcM4tCG4vdX9b0Ri+VYo
        LiHkmxenK0mgBwYFK4EEACKhZANiAASvggNRMynXOObY9QW4gJXCwgsNa/8vcjHK
        wgzyqfXUzv3PbiZbDVYtYT7FMzd84CmX9BEtsE8bQS2Ci7q0Izp9aRUjCiTlUuAZ
        XMhBcGTy1e65CRjbCNM4A8w0/K30x4k=
        -----END EC PRIVATE KEY-----

monitoring:
    key: qowidhqowidhqoihdqodwh
`)},
		{"two signers", true, []byte(`
server:
    listen: "localhost:8000"
    noncecachesize: 64

heartbeat:
    hsmchecktimeout: 100ms
    dbchecktimeout: 150ms

signers:
    - id: testsigner1
      privatekey: |
        -----BEGIN EC PRIVATE KEY-----
        MIGkAgEBBDBe7dXZ/epqVkrRWbStmwe2WyTcpWJ5cCbrqcM4tCG4vdX9b0Ri+VYo
        LiHkmxenK0mgBwYFK4EEACKhZANiAASvggNRMynXOObY9QW4gJXCwgsNa/8vcjHK
        wgzyqfXUzv3PbiZbDVYtYT7FMzd84CmX9BEtsE8bQS2Ci7q0Izp9aRUjCiTlUuAZ
        XMhBcGTy1e65CRjbCNM4A8w0/K30x4k=
        -----END EC PRIVATE KEY-----

    - id: testsigner2
      privatekey: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIBOgIBAAJBALhlXvMK5hIgGGRgdUycR8FWAmZC5bOeUrLr9SWep2NnR9nmBDgS
        AYYFTraBw2se+oagYyWjccDnbJR9GPHarWkCAwEAAQJAey1kbxCxvhvoj20MDoA7
        QsB02+EGVqWFcvZCjb3c7X4XZS0Oe1y1TJSmyL7oEepuL3NTgXYib+RSLT8vph8u
        zQIhANzuVRWzm7sSgTsPgg/P+q/5O2BXzoY/QpWdDb8DWEVjAiEA1apqeW9u38o3
        xpjJBa7tTNzgmuZtupFvB7baO8So0cMCICjTxld3VI0Sk10ltYRUi+AfL7DTKTA3
        2ocpedPVu2c/AiEAuCx0KQa3sKmTWFmcdYyqOeXuqTbVAMuZxDGGfZxv1JcCIA2v
        84l6Qav0l4A3NDdT+cotbnDqQ5wjF+UZ8uwsBwSl
        -----END RSA PRIVATE KEY-----

authorizations:
    - id: tester
      key: oiqwhfoqihfoiqeheouqqouhfdq
      signers:
          - testsigner1
`)},
		{"missing heartbeat config", false, []byte(`
server:
    listen: "localhost:8000"
    noncecachesize: 64

signers:
    - id: testsigner1
      privatekey: |
        -----BEGIN EC PRIVATE KEY-----
        MIGkAgEBBDBe7dXZ/epqVkrRWbStmwe2WyTcpWJ5cCbrqcM4tCG4vdX9b0Ri+VYo
        LiHkmxenK0mgBwYFK4EEACKhZANiAASvggNRMynXOObY9QW4gJXCwgsNa/8vcjHK
        wgzyqfXUzv3PbiZbDVYtYT7FMzd84CmX9BEtsE8bQS2Ci7q0Izp9aRUjCiTlUuAZ
        XMhBcGTy1e65CRjbCNM4A8w0/K30x4k=
        -----END EC PRIVATE KEY-----

    - id: testsigner2
      privatekey: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIBOgIBAAJBALhlXvMK5hIgGGRgdUycR8FWAmZC5bOeUrLr9SWep2NnR9nmBDgS
        AYYFTraBw2se+oagYyWjccDnbJR9GPHarWkCAwEAAQJAey1kbxCxvhvoj20MDoA7
        QsB02+EGVqWFcvZCjb3c7X4XZS0Oe1y1TJSmyL7oEepuL3NTgXYib+RSLT8vph8u
        zQIhANzuVRWzm7sSgTsPgg/P+q/5O2BXzoY/QpWdDb8DWEVjAiEA1apqeW9u38o3
        xpjJBa7tTNzgmuZtupFvB7baO8So0cMCICjTxld3VI0Sk10ltYRUi+AfL7DTKTA3
        2ocpedPVu2c/AiEAuCx0KQa3sKmTWFmcdYyqOeXuqTbVAMuZxDGGfZxv1JcCIA2v
        84l6Qav0l4A3NDdT+cotbnDqQ5wjF+UZ8uwsBwSl
        -----END RSA PRIVATE KEY-----

authorizations:
    - id: tester
      key: oiqwhfoqihfoiqeheouqqouhfdq
      signers:
          - testsigner1
`)},

		{"bogus yaml", false, []byte(`{{{{{{{`)},
		{"yaml with tabs", false, []byte(`
server:
	listen: "localhost:8000"
	noncecachesize: 64

heartbeat:
    hsmchecktimeout: 100ms
    dbchecktimeout: 150ms

signers:
      - privatekey: |
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEII+Is30aP9wrB/H6AkKrJjMG8EVY2WseSFHTfWGCIk7voAoGCCqGSM49
        AwEHoUQDQgAEMdzAsqkWQiP8Fo89qTleJcuEjBtp2c6z16sC7BAS5KXvUGghURYq
        3utZw8En6Ik/4Om8c7EW/+EO+EkHShhgdA==
        -----END EC PRIVATE KEY-----
authorizations:
	- tester
`)},
	}
	for i, testcase := range testcases {
		var conf configuration
		// write conf file to /tmp and read it back
		fd, err := os.CreateTemp("", "autographtestconf")
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

func TestDuplicateSigners(t *testing.T) {
	t.Parallel()

	var conf configuration
	// write conf file to /tmp and read it back
	fd, err := os.CreateTemp("", "autographtestconf")
	if err != nil {
		t.Fatal(err)
	}
	fi, err := fd.Stat()
	if err != nil {
		t.Fatal(err)
	}
	filename := fmt.Sprintf("%s/%s", os.TempDir(), fi.Name())
	_, err = fd.Write([]byte(`
server:
    listen: "localhost:8000"
    noncecachesize: 64

heartbeat:
    hsmchecktimeout: 100ms
    dbchecktimeout: 150ms

signers:
    - id: testsigner1
      privatekey: |
        -----BEGIN EC PRIVATE KEY-----
        XMhBcGTy1e65CRjbCNM4A8w0/K30x4k=
        -----END EC PRIVATE KEY-----

    - id: testsigner1
      privatekey: |
        -----BEGIN RSA PRIVATE KEY-----
        84l6Qav0l4A3NDdT+cotbnDqQ5wjF+UZ8uwsBwSl
        -----END RSA PRIVATE KEY-----
`))

	if err != nil {
		t.Fatal(err)
	}
	fd.Close()
	err = conf.loadFromFile(filename)
	if err != nil {
		t.Fatalf("config parsing failed and should have passed: %v", err)
	}
	// initialize signers from the configuration
	// and store them into the autographer handler
	dupag := newAutographer(conf.Server.NonceCacheSize)
	err = dupag.addSigners(conf.Signers)
	if err == nil {
		t.Fatalf("should have failed with duplicate signers but didn't")
	}
	os.Remove(filename)
}

func TestDuplicateAuthorization(t *testing.T) {
	t.Parallel()

	var conf configuration
	// write conf file to /tmp and read it back
	fd, err := os.CreateTemp("", "autographtestconf")
	if err != nil {
		t.Fatal(err)
	}
	fi, err := fd.Stat()
	if err != nil {
		t.Fatal(err)
	}
	filename := fmt.Sprintf("%s/%s", os.TempDir(), fi.Name())
	_, err = fd.Write([]byte(`
server:
    listen: "localhost:8000"
    noncecachesize: 64

heartbeat:
    hsmchecktimeout: 100ms
    dbchecktimeout: 150ms

signers:
    - id: testsigner1
      type: contentsignature
      x5u: https://foo.example.com/chains/certificates.pem
      privatekey: |
          -----BEGIN EC PARAMETERS-----
          BggqhkjOPQMBBw==
          -----END EC PARAMETERS-----
          -----BEGIN EC PRIVATE KEY-----
          MHcCAQEEII+Is30aP9wrB/H6AkKrJjMG8EVY2WseSFHTfWGCIk7voAoGCCqGSM49
          AwEHoUQDQgAEMdzAsqkWQiP8Fo89qTleJcuEjBtp2c6z16sC7BAS5KXvUGghURYq
          3utZw8En6Ik/4Om8c7EW/+EO+EkHShhgdA==
          -----END EC PRIVATE KEY-----

authorizations:
    - id: tester
      key: oiqwhfoqihfoiqeheouqqouhfdq
      signers:
          - testsigner1
    - id: tester
      key: oiqwhfoqihfoiqeheouqqouhfdq
      signers:
          - testsigner1
`))

	if err != nil {
		t.Fatal(err)
	}
	fd.Close()
	err = conf.loadFromFile(filename)
	if err != nil {
		t.Fatalf("config parsing failed and should have passed: %v", err)
	}
	// initialize signers from the configuration
	// and store them into the autographer handler
	dupag := newAutographer(conf.Server.NonceCacheSize)
	err = dupag.addSigners(conf.Signers)
	if err != nil {
		t.Fatal(err)
	}
	err = dupag.addAuthorizations(conf.Authorizations)
	if err == nil {
		t.Fatalf("should have failed with duplicate authorizations but succeeded")
	}
	os.Remove(filename)
}

func TestUnknownSignerInAuthorization(t *testing.T) {
	t.Parallel()

	var conf configuration
	// write conf file to /tmp and read it back
	fd, err := os.CreateTemp("", "autographtestconf")
	if err != nil {
		t.Fatal(err)
	}
	fi, err := fd.Stat()
	if err != nil {
		t.Fatal(err)
	}
	filename := fmt.Sprintf("%s/%s", os.TempDir(), fi.Name())
	_, err = fd.Write([]byte(`
server:
    listen: "localhost:8000"
    noncecachesize: 64

heartbeat:
    hsmchecktimeout: 100ms
    dbchecktimeout: 150ms

signers:
    - id: testsigner1
      type: contentsignature
      x5u: https://foo.example.com/chains/certificates.pem
      privatekey: |
          -----BEGIN EC PARAMETERS-----
          BggqhkjOPQMBBw==
          -----END EC PARAMETERS-----
          -----BEGIN EC PRIVATE KEY-----
          MHcCAQEEII+Is30aP9wrB/H6AkKrJjMG8EVY2WseSFHTfWGCIk7voAoGCCqGSM49
          AwEHoUQDQgAEMdzAsqkWQiP8Fo89qTleJcuEjBtp2c6z16sC7BAS5KXvUGghURYq
          3utZw8En6Ik/4Om8c7EW/+EO+EkHShhgdA==
          -----END EC PRIVATE KEY-----

authorizations:
    - id: tester
      key: oiqwhfoqihfoiqeheouqqouhfdq
      signers:
          - testsigner2
`))

	if err != nil {
		t.Fatal(err)
	}
	fd.Close()
	err = conf.loadFromFile(filename)
	if err != nil {
		t.Fatalf("config parsing failed and should have passed: %v", err)
	}
	// initialize signers from the configuration
	// and store them into the autographer handler
	ag := newAutographer(conf.Server.NonceCacheSize)
	err = ag.addSigners(conf.Signers)
	if err != nil {
		t.Fatal(err)
	}
	err = ag.addAuthorizations(conf.Authorizations)
	if err == nil {
		t.Fatalf("should have failed with unknown signer in authorization but succeeded")
	}
	os.Remove(filename)
}

// An authorization without at least one signer configured must fail
func TestAuthWithoutSigner(t *testing.T) {
	t.Parallel()
	var authorizations = []authorization{
		authorization{
			ID: "alice",
		},
	}
	tmpag := newAutographer(1)
	tmpag.addSigners(conf.Signers)
	err := tmpag.addAuthorizations(authorizations)
	if err == nil {
		t.Fatalf("should have failed with must have one signer but succeeded")
	}
}

func TestConfigLoadFileNotExist(t *testing.T) {
	t.Parallel()

	var conf configuration
	err := conf.loadFromFile("/tmp/a/b/c/d/e/f/e/d/c/b/a/oned97fy2qoelfahd018oehfa9we8ohf219")
	if err == nil {
		t.Fatalf("should have file with file not found, but passed")
	}
}

func TestDefaultPort(t *testing.T) {
	t.Parallel()

	expected := "0.0.0.0:8000"
	_, listen, _ := parseArgsAndLoadConfig([]string{})
	if listen != expected {
		t.Errorf("expected listen %s got %s", expected, listen)
	}
}

func TestPortOverride(t *testing.T) {
	t.Parallel()

	expected := "0.0.0.0:8080"
	_, listen, _ := parseArgsAndLoadConfig([]string{"-p", "8080"})
	if listen != expected {
		t.Errorf("expected listen %s got %s", expected, listen)
	}
}
