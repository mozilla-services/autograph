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

// Package contract implements contract tests for fakekms
// go/mocks#fakes-need-tests
package contract

import (
	"context"
	"flag"
	"hash/crc32"
	"log"
	"os"
	"testing"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/kms/integrations/fakekms"
	"google.golang.org/api/option"
	"google.golang.org/grpc"

	"google.golang.org/protobuf/types/known/wrapperspb"
)

// variables used by test cases
var (
	client            *testClient
	location          string
	asyncPollInterval time.Duration
)

func TestMain(m *testing.M) {
	flag.StringVar(&location, "location", "projects/oss-tools-test/locations/us-central1",
		"the project and location to use for testing")
	flag.DurationVar(&asyncPollInterval, "async_poll_interval", time.Millisecond,
		"the duration to sleep between Get requests when waiting on asynchronous events")
	kmsEndpoint := flag.String("kms_endpoint", "",
		"the KMS endpoint to use for requests; if unspecified, fakekms will be used")
	quotaProject := flag.String("quota_project", "",
		"the quota project to use with real KMS; ignored for fake runs")
	flag.Parse()

	if *kmsEndpoint == "" {
		testFakeKMS(m)
	} else {
		testRealKMS(m, *kmsEndpoint, *quotaProject)
	}
}

func testRealKMS(m *testing.M, kmsEndpoint, quotaProject string) {
	initCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	opts := []option.ClientOption{option.WithEndpoint(kmsEndpoint)}
	if quotaProject != "" {
		opts = append(opts, option.WithQuotaProject(quotaProject))
	}

	c, err := kms.NewKeyManagementClient(initCtx, opts...)
	if err != nil {
		log.Fatalf("error creating KMS client: %v", err)
	}
	defer c.Close()

	client = &testClient{c}
	os.Exit(m.Run())
}

func testFakeKMS(m *testing.M) {
	s, err := fakekms.NewServer()
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	cc, err := grpc.Dial(s.Addr.String(), grpc.WithInsecure())
	if err != nil {
		log.Fatalf("error opening gRPC client connection to fakekms: %v", err)
	}

	initCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := kms.NewKeyManagementClient(initCtx, option.WithGRPCConn(cc))
	if err != nil {
		log.Fatalf("error creating KMS client: %v", err)
	}
	defer c.Close()

	client = &testClient{c}
	os.Exit(m.Run())
}

var crc32CTable = crc32.MakeTable(crc32.Castagnoli)

func verifyCRC32C(t *testing.T, data []byte, checksum *wrapperspb.Int64Value) {
	t.Helper()

	want := int64(crc32.Checksum(data, crc32CTable))
	if checksum == nil || checksum.Value != want {
		t.Errorf("checksum=%v, want %d", checksum, want)
	}
}
