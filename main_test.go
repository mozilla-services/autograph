// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func TestConfigLoad(t *testing.T) {
	testcases := []struct {
		pass bool
		data []byte
	}{
		{true, []byte(`
server:
    listen: "localhost:8000"

signers:
    - privatekey: "MIGkAgEBBDAzX2TrGOr0WE92AbAl+nqnpqh25pKCLYNMTV2hJHztrkVPWOp8w0mhscIodK8RMpagBwYFK4EEACKhZANiAATiTcWYbt0Wg63dO7OXvpptNG0ryxv+v+JsJJ5Upr3pFus5fZyKxzP9NPzB+oFhL/xw3jMx7X5/vBGaQ2sJSiNlHVkqZgzYF6JQ4yUyiqTY7v67CyfUPA1BJg/nxOS9m3o="
      publickey: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE4k3FmG7dFoOt3Tuzl76abTRtK8sb/r/ibCSeVKa96RbrOX2ciscz/TT8wfqBYS/8cN4zMe1+f7wRmkNrCUojZR1ZKmYM2BeiUOMlMoqk2O7+uwsn1DwNQSYP58TkvZt6"
      authorizedusers:
          - tester`)},
		{true, []byte(`
server:
    listen: "localhost:8000"

signers:
    - privatekey: "MIGkAgEBBDAzX2TrGOr0WE92AbAl+nqnpqh25pKCLYNMTV2hJHztrkVPWOp8w0mhscIodK8RMpagBwYFK4EEACKhZANiAATiTcWYbt0Wg63dO7OXvpptNG0ryxv+v+JsJJ5Upr3pFus5fZyKxzP9NPzB+oFhL/xw3jMx7X5/vBGaQ2sJSiNlHVkqZgzYF6JQ4yUyiqTY7v67CyfUPA1BJg/nxOS9m3o="
      publickey: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE4k3FmG7dFoOt3Tuzl76abTRtK8sb/r/ibCSeVKa96RbrOX2ciscz/TT8wfqBYS/8cN4zMe1+f7wRmkNrCUojZR1ZKmYM2BeiUOMlMoqk2O7+uwsn1DwNQSYP58TkvZt6"
      authorizedusers:
          - tester
    - privatekey: "MIGkAgEBBDs5fZyKxzP9NPzB+oFhL/xw3jMx7X5/vBGaQ2sJSiNlHVkqZgzYF6JQ4yUyiqTY7v67CyfUPA1BJg/nxOS9m3o="
      publickey: "MHYwEAYHKoZYS/8cN4zMe1+f7wRmkNrCUojZR1ZKmYM2BeiUOMlMoqk2O7+uwsn1DwNQSYP58TkvZt6"
      authorizedusers:
          - bob
`)},
		// bogus yaml
		{false, []byte(`{{{{{{{`)},
		// yaml with tabs
		{false, []byte(`
server:
	listen: "localhost:8000"

signers:
	- privatekey: "MIGkAgEBBDAzX2TrGOr0WE92AbAl+nqnpqh25pKCLYNMTV2hJHztrkVPWOp8w0mhscIodK8RMpagBwYFK4EEACKhZANiAATiTcWYbt0Wg63dO7OXvpptNG0ryxv+v+JsJJ5Upr3pFus5fZyKxzP9NPzB+oFhL/xw3jMx7X5/vBGaQ2sJSiNlHVkqZgzYF6JQ4yUyiqTY7v67CyfUPA1BJg/nxOS9m3o="
	  publickey: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE4k3FmG7dFoOt3Tuzl76abTRtK8sb/r/ibCSeVKa96RbrOX2ciscz/TT8wfqBYS/8cN4zMe1+f7wRmkNrCUojZR1ZKmYM2BeiUOMlMoqk2O7+uwsn1DwNQSYP58TkvZt6"
	  authorizedusers:
		- tester
`)},
	}
	for i, testcase := range testcases {
		var conf configuration
		// write conf file to /tmp and read it back
		fd, err := ioutil.TempFile("", "tlsobsrunnertestconf")
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
			t.Fatalf("testcase %d failed and should have passed: %v",
				i, err)
		}
		if err == nil && !testcase.pass {
			t.Fatalf("testcase %d passed and should have failed", i)
		}
		os.Remove(filename)
	}
}

func TestConfigLoadFileNotExist(t *testing.T) {
	var conf configuration
	err := conf.loadFromFile("/tmp/a/b/c/d/e/f/e/d/c/b/a/oned97fy2qoelfahd018oehfa9we8ohf219")
	if err == nil {
		t.Fatalf("should have file with file not found, but passed")
	}
}
