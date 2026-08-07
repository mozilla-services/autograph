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

// buildsigner is a simple CLI tool that performs a signature over standard
// input and writes it to standard output.
package main

import (
	"context"
	"flag"
	"io"
	"log"
	"os"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/sethvargo/go-gcpkms/pkg/gcpkms"
)

func signStdinToStdout(ctx context.Context, ckvName string) error {
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return err
	}

	signer, err := gcpkms.NewSigner(ctx, kmsClient, ckvName)
	if err != nil {
		return err
	}

	hasher := signer.DigestAlgorithm().New()
	if _, err := io.Copy(hasher, os.Stdin); err != nil {
		return err
	}
	digest := hasher.Sum(nil)

	sig, err := signer.Sign(nil, digest, nil)
	if err != nil {
		return err
	}
	os.Stdout.Write(sig)
	return nil
}

func main() {
	signingCkv := flag.String("signing_key", "",
		"The full name of a KMS CryptoKeyVersion to sign with.")
	flag.Parse()

	if *signingCkv == "" {
		log.Fatal("flag -signing_key is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := signStdinToStdout(ctx, *signingCkv); err != nil {
		log.Fatal(err)
	}
}
