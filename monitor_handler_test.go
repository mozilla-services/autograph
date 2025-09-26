package main

import (
	"bytes"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/mozilla-services/autograph/signer"
)

func TestMonitorNoConfig(t *testing.T) {
	tmpag := newAutographer(1)
	var nomonitor configuration
	err := tmpag.addMonitoring(nomonitor.Monitoring)
	if err != nil {
		t.Fatal("adding monitoring configuration failed")
	}
	_, err = tmpag.getAuthByID(monitorAuthID)
	if err == nil {
		t.Fatal("monitor configuration found when none was passed")
	}
}

func TestMonitorAddDuplicate(t *testing.T) {
	tmpag := newAutographer(1)
	var monitorconf configuration
	monitorconf.Monitoring.Key = "xxxxxxx"

	defer func() {
		if e := recover(); e != nil {
			if e != `user 'monitor' is reserved for monitoring, duplication is not permitted` {
				t.Fatalf("expected authorization loading to fail with duplicate error but got: %v", e)
			}
		}
	}()
	// Adding the first one will pass, adding the second one will trigger the panic
	_ = tmpag.addMonitoring(monitorconf.Monitoring)
	_ = tmpag.addMonitoring(monitorconf.Monitoring)
}

func TestMonitorBadRequest(t *testing.T) {
	ag, conf := newTestAutographer(t)
	mo := newMonitor(ag, conf.MonitorInterval)

	var TESTCASES = []struct {
		user     string
		key      string
		endpoint string
		method   string
		body     string
	}{
		// wrong method
		{``, ``, `/__monitor__`, `POST`, ``},
		{``, ``, `/__monitor__`, `PUT`, ``},
		{``, ``, `/__monitor__`, `HEAD`, ``},
		{``, ``, `/__monitor__`, `DELETE`, ``},
		// shouldn't have a request body
		{`monitor`, conf.Monitoring.Key, `/__monitor__`, `GET`, `[{"input":"y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d"}]`},
		// should use the monitor user
		{conf.Authorizations[0].ID, conf.Authorizations[0].Key, `/__monitor__`, `GET`, ``},
		// should use the monitoring key
		{`monitor`, conf.Authorizations[0].Key, `/__monitor__`, `GET`, ``},
	}
	for i, testcase := range TESTCASES {
		body := strings.NewReader(testcase.body)
		req, err := http.NewRequest(testcase.method, "http://foo.bar"+testcase.endpoint, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		authheader := getAuthHeader(req, testcase.user, testcase.key, sha256.New, id(), "application/json", []byte(testcase.body))
		req.Header.Set("Authorization", authheader)
		w := httptest.NewRecorder()
		mo.handleMonitor(w, req)
		if w.Code == http.StatusCreated {
			t.Fatalf("test case %d failed with %d: %s", i, w.Code, w.Body.String())
		}
	}
}

func TestMonitorReturnsAllFailures(t *testing.T) {
	ag, conf := newTestAutographer(t)
	testPrivateKey := `-----BEGIN PGP PRIVATE KEY BLOCK-----

lQHYBGbt/oUBBAC8q+ta2NFHKd5u63Atnpa9g8uU4lXyRkUeROqdS09fDEgNuip9
fi6//CjV9ZwGTB5OTzMafkZczdDmDFZ7RsqvVlr2Cp8/mXP7Eg70neycwzK1NF79
QItQaNicZLmtAGYzO9ANsTbkYbtipcCxtmXlxHgm7XxS98oLYVStw7YvDQARAQAB
AAP5AbOVesCPnpqk5JfKPExrrDJ2+1DIsqR6/dPs0IjvKyU816XIhmGrkpiIzeCi
u9C9DeVoOHoLhhG8K3RIB8fZBke/rc58XCagpNt9C4xSINmW5bs3Ee8RnJe5yqUv
HI7C1/dIWbrjqPw5P2oH24R6DRvaDtsp4goKfw4kAE7dPDECANXCxWzhLWD6WsyD
e7zzWtk9XMtvyblCSJ1Nx2DjgASwb/dMlxcbf69XvxXO5mKAvIkCU9dYSUn18PrV
9XIgahkCAOHz/davmlU84KarCD+U4f6gpKMXCxmFuuHTsuE0Q7S/KiQxtbyLvxI+
QcwteXbDFEgM0/yY9JbT7nbJFVuOsxUCAJyVygUTZPMjYEE1xUKukXLAu0deWt9l
PZTI1QbbQkSma9voBKwLC7OXW68XbfD1sF+8rs0dzdWwVGDy0RcUVAynULQkVGVz
dHkgTWNUZXN0ZXJzb24gPHRlc3RAbW96aWxsYS5jb20+iNQEEwEKAD4WIQRQZBMS
CHjMpz9U89kVPrmVYCOelwUCZu3+hQIbAwUJAAFRgAULCQgHAgYVCgkICwIEFgID
AQIeAQIXgAAKCRAVPrmVYCOel1FGA/0YG0eDNgHL9vfHpfsl2m/owFDghEde3ndY
UE6nrK6y7krpPiKNY7E5LYffghakJWg+ls/BKvj42kDdp9bPUxXBktOdXigx76VI
1Ut9ZQY1xAOxea1wUyGF53z31KNQDF/M0Wf4ev9PYgSX6btmMEBky9kUdFx40YOl
ffn6lwTKAg==
=nPnr
-----END PGP PRIVATE KEY BLOCK-----`
	testPublicKey := `-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EZu3+hQEEALyr61rY0Ucp3m7rcC2elr2Dy5TiVfJGRR5E6p1LT18MSA26Kn1+
Lr/8KNX1nAZMHk5PMxp+RlzN0OYMVntGyq9WWvYKnz+Zc/sSDvSd7JzDMrU0Xv1A
i1Bo2Jxkua0AZjM70A2xNuRhu2KlwLG2ZeXEeCbtfFL3ygthVK3Dti8NABEBAAG0
JFRlc3R5IE1jVGVzdGVyc29uIDx0ZXN0QG1vemlsbGEuY29tPojUBBMBCgA+FiEE
UGQTEgh4zKc/VPPZFT65lWAjnpcFAmbt/oUCGwMFCQABUYAFCwkIBwIGFQoJCAsC
BBYCAwECHgECF4AACgkQFT65lWAjnpdRRgP9GBtHgzYBy/b3x6X7Jdpv6MBQ4IRH
Xt53WFBOp6yusu5K6T4ijWOxOS2H34IWpCVoPpbPwSr4+NpA3afWz1MVwZLTnV4o
Me+lSNVLfWUGNcQDsXmtcFMhhed899SjUAxfzNFn+Hr/T2IEl+m7ZjBAZMvZFHRc
eNGDpX35+pcEygI=
=JC6I
-----END PGP PUBLIC KEY BLOCK-----`

	err := ag.addSigners([]signer.Configuration{{
		ID:         "testErr1",
		Type:       "gpg2",
		Mode:       "gpg2",
		KeyID:      "153EB99560239E97",
		PrivateKey: testPrivateKey,
		PublicKey:  testPublicKey,
	}, {
		ID:         "testErr2",
		Type:       "gpg2",
		Mode:       "gpg2",
		KeyID:      "153EB99560239E97",
		PrivateKey: testPrivateKey,
		PublicKey:  testPublicKey,
	},
	})
	if err != nil {
		t.Fatalf("adding signers failed: %v", err)
	}
	mo := newMonitor(ag, conf.MonitorInterval)

	var empty []byte
	req, err := http.NewRequest("GET", "http://foo.bar/__monitor__", bytes.NewReader(empty))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	authheader := getAuthHeader(req, monitorAuthID, conf.Monitoring.Key,
		sha256.New, id(), "application/json", empty)
	req.Header.Set("Authorization", authheader)
	w := httptest.NewRecorder()

	mo.handleMonitor(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatal("expected a 500 response from monitor in TestMonitorReturnsAllFailures")
	}

	bodyBytes, _ := io.ReadAll(w.Result().Body)
	if match, _ := regexp.Match("1. data signing for testErr1 failed", bodyBytes); !match {
		t.Fatal("Didn't find first error in response body")
	}
	if match, _ := regexp.Match("2. data signing for testErr2 failed", bodyBytes); !match {
		t.Fatal("Didn't find second error in response body")
	}
}
