package main

import (
	"log"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// load the signers
	err := conf.loadFromFile(os.Getenv("GOPATH") + "/src/go.mozilla.org/autograph/tools/autograph-edge/autograph-edge.yaml")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("configuration: %+v\n", conf)
	// run the tests and exit
	r := m.Run()
	os.Exit(r)
}

func TestAuth(t *testing.T) {
	var testcases = []struct {
		expect bool
		token  string
		user   string
		signer string
	}{
		{true, "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547", "alice", "extensions-ecdsa"},
		{true, "dd095f88adbf7bdfa18b06e23e83896107d7e0f969f7415830028fa2c1ccf9fd", "alice", "testapp-android"},
		{false, "c4180d2963fffdcd1cd5a1a343225288b964d8934", "", ""},
		{false, "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67c98712jh", "", ""},
	}
	for i, testcase := range testcases {
		auth, err := authorize(testcase.token)
		if err != nil {
			if err == errInvalidToken && !testcase.expect {
				continue
			}
			if testcase.expect {
				t.Fatalf("testcase %d expected to succeed but failed with %s", i, err)
			}
		}
		if auth.User != testcase.user {
			t.Fatalf("testcase %d failed: expected user %q, got %q", i, testcase.user, auth.User)
		}
		if auth.Signer != testcase.signer {
			t.Fatalf("testcase %d failed: expected signer %q, got %q", i, testcase.signer, auth.Signer)
		}
	}
}
