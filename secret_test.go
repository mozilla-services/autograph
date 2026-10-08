// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"net"
	"testing"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/mozilla-services/yaml"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type fakeServer struct {
	secretmanagerpb.UnimplementedSecretManagerServiceServer
}

func (f *fakeServer) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	fakeData, _ := yaml.Marshal(map[string]string{
		"privatekey":    "privatekey",
		"passphrase":    "passphrase",
		"issuerprivkey": "issuerprivkey",
	})

	resp := &secretmanagerpb.AccessSecretVersionResponse{
		Name: req.Name,
		Payload: &secretmanagerpb.SecretPayload{
			Data: fakeData,
		},
	}
	return resp, nil
}

func TestSecretMapRead(t *testing.T) {
	ctx := context.Background()

	fake := &fakeServer{}
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}

	gsrv := grpc.NewServer()
	secretmanagerpb.RegisterSecretManagerServiceServer(gsrv, fake)
	fakeAddr := l.Addr().String()
	go func() {
		if err := gsrv.Serve(l); err != nil {
			panic(err)
		}
	}()

	client, err := secretmanager.NewClient(ctx,
		option.WithEndpoint(fakeAddr),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)
	if err != nil {
		t.Fatal(err)
	}

	testMap, err := getSecretMap(client, ctx, "fake-project", "fake-secret")
	if err != nil {
		t.Fatal(err)
	}
	if testMap["privatekey"] != "privatekey" {
		t.Error("Unable to retrieve privatekey from secret")
	}
	if testMap["passphrase"] != "passphrase" {
		t.Error("Unable to retrieve passphrase from secret")
	}
	if testMap["issuerprivkey"] != "issuerprivkey" {
		t.Error("Unable to retrieve issuerprivkey from secret")
	}
}
