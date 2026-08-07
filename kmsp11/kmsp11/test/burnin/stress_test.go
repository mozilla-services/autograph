// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stresstest

import (
	"context"
	"fmt"
	"os"
	"path"
	"testing"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/kms/integrations/fakekms"
	"github.com/bazelbuild/rules_go/go/tools/bazel"
	"github.com/miekg/pkcs11"
	"google.golang.org/api/option"
	"google.golang.org/grpc"

	"cloud.google.com/go/kms/apiv1/kmspb"
)

const (
	GoogleDefined = (0x80000000 | 0x1E100)
	KMSAlgorithm  = (GoogleDefined | 0x01)
)

var (
	p      *pkcs11.Ctx
	server *fakekms.Server
)

func init() {
	lib, err := bazel.Runfile("kmsp11/main/libkmsp11.so")
	if err != nil {
		errorString := fmt.Sprintf("error locating KMS PKCS11 .so library: %v", err)
		panic(errorString)
	}
	p = pkcs11.New(lib)
}

const configVar = "KMS_PKCS11_CONFIG"

type testEnv struct {
	tb                     testing.TB
	testDir, logDir        string
	envVarSet, initialized bool
}

func (env *testEnv) Close() {
	if env.initialized {
		if err := p.Finalize(); err != nil {
			env.tb.Errorf("error calling C_Finalize: %v", err)
		}
	}
	if env.envVarSet {
		if err := os.Unsetenv(configVar); err != nil {
			env.tb.Errorf("error unsetting %q: %v", configVar, err)
		}
	}

	if env.tb.Failed() {
		env.tb.Log("attempting to extract library logs to supplmement test failure information")
		entries, err := os.ReadDir(env.logDir)
		if err != nil {
			env.tb.Logf("failed to read from log directory: %v", err)
		}

		for _, entry := range entries {
			fullPath := path.Join(env.logDir, entry.Name())
			fileBytes, err := os.ReadFile(fullPath)
			if err != nil {
				env.tb.Logf("error reading file %q: %v", fullPath, err)
			}
			env.tb.Logf("contents of %q: %s", fullPath, string(fileBytes))
		}
	}

	os.RemoveAll(env.testDir)
}

const configTemplate = `---
kms_endpoint: %q
user_project_override: oss-tools-test
tokens:
  - key_ring: projects/oss-tools-test/locations/us-central1/keyRings/stress-test
log_directory: %q
use_insecure_grpc_channel_credentials: 1
refresh_interval_secs: 1
`

func initLibrary(t *testing.T) func() {
	t.Helper()
	env := &testEnv{tb: t}

	var err error
	if env.testDir, err = os.MkdirTemp("", "pkcs11-benchmark"); err != nil {
		t.Fatalf("error creating test directory: %v", err)
	}

	env.logDir = path.Join(env.testDir, "log")
	if err = os.Mkdir(env.logDir, 0755); err != nil {
		env.Close()
		t.Fatalf("error creating log directory: %v", err)
	}

	config := fmt.Sprintf(configTemplate, server.Addr.String(), env.logDir)
	configFile := path.Join(env.testDir, "config.yaml")
	if err = os.WriteFile(configFile, []byte(config), 0644); err != nil {
		env.Close()
		t.Fatalf("error writing config file: %v", err)
	}

	if err = os.Setenv(configVar, configFile); err != nil {
		env.Close()
		t.Fatalf("error setting %q: %v", configVar, err)
	}
	env.envVarSet = true

	if err := p.Initialize(); err != nil {
		env.Close()
		t.Fatalf("error initializing: %v", err)
	}
	env.initialized = true

	return env.Close
}

func newSessionHandle(t *testing.T) (pkcs11.SessionHandle, func()) {
	t.Helper()

	// Slots are always assigned 0-index according to how they exist in YAML config,
	// hardcoding 0 here. Making the session read-write to allow key creation.
	session, err := p.OpenSession(0, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	return session, func() {
		if err := p.CloseSession(session); err != nil {
			t.Fatal(err)
		}
	}
}

func createKey(t *testing.T, i int) (pub, prv pkcs11.ObjectHandle) {
	t.Helper()

	session, closeSession := newSessionHandle(t)
	defer closeSession()

	ckvName := fmt.Sprintf("%s%d", "key-", i)
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, ckvName),
		pkcs11.NewAttribute(KMSAlgorithm, uint(kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256)),
	}
	var pbk, pvk pkcs11.ObjectHandle
	pbk, pvk, err := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		nil, privateKeyTemplate)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	return pbk, pvk
}

func destroyKey(t *testing.T, prv pkcs11.ObjectHandle) {
	t.Helper()

	session, closeSession := newSessionHandle(t)
	defer closeSession()

	if err := p.DestroyObject(session, prv); err != nil {
		t.Fatalf("DestroyObject failed: %s\n", err)
	}
}

func TestKeyCache(t *testing.T) {
	var err error
	server, err = fakekms.NewServer()
	if err != nil {
		t.Fatalf("error starting fakekms server", err)
	}
	defer server.Close()

	cc, err := grpc.Dial(server.Addr.String(), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("error opening gRPC client connection to fakekms: %v", err)
	}

	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx, option.WithGRPCConn(cc))
	if err != nil {
		t.Fatalf("error creating KMS client: %v", err)
	}
	_, err = client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    "projects/oss-tools-test/locations/us-central1",
		KeyRingId: "stress-test",
	})
	if err != nil {
		t.Fatalf("error creating KMS keyring: %v", err)
	}
	defer client.Close()

	finalize := initLibrary(t)
	defer finalize()

	// Total runtime for 600 loops: ~5 minutes
	for i := 0; i < 600; i++ {
		_, prv := createKey(t, i)
		destroyKey(t, prv)
	}
}
