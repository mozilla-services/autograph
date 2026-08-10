// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package signtooltest

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"os"
	"os/exec"
	"testing"
	"time"

	"installtestlib"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/kms/integrations/fakekms"
	"github.com/google/uuid"
	"github.com/sethvargo/go-gcpkms/pkg/gcpkms"
	"google.golang.org/api/option"
	"google.golang.org/grpc"

	"cloud.google.com/go/kms/apiv1/kmspb"
)

func generateSelfSignedCertTempFile(t *testing.T, signer *gcpkms.Signer, alg x509.SignatureAlgorithm) string {
	relTime := time.Now()
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Certificate"},
		SerialNumber:          big.NewInt(1),
		NotBefore:             relTime.AddDate(0, 0, -1),
		NotAfter:              relTime.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    alg,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}

	certFile, err := os.CreateTemp("", "cert-*.cer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certFile.Write(cert); err != nil {
		t.Fatal(err)
	}
	certFile.Close()

	return certFile.Name()
}

func signtoolLocation() string {
	// Only 32-bit signtool is part of the PATH on docker images.
	// When the kokoro image is updated, this needs to be updated too.
	return "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.26100.0\\x64\\signtool.exe"
}

func TestSigntoolSuccess(t *testing.T) {
	tests := []struct {
		name    string
		kms_alg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
		alg     x509.SignatureAlgorithm
		sha     string
	}{
		{"ECDSA256", kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, x509.ECDSAWithSHA256, "sha256"},
		{"ECDSA384", kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384, x509.ECDSAWithSHA384, "sha384"},
		{"RSA2048SHA256", kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, x509.SHA256WithRSA, "sha256"},
		{"RSA3072SHA256", kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256, x509.SHA256WithRSA, "sha256"},
		{"RSA4096SHA256", kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256, x509.SHA256WithRSA, "sha256"},
		{"RSA4096SHA512", kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512, x509.SHA512WithRSA, "sha512"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			installtestlib.MustInstall(t, ctx)
			defer installtestlib.MustUninstall(t, ctx)

			srv, err := fakekms.NewServer()
			if err != nil {
				t.Fatal(err)
			}

			clientConn, err := grpc.Dial(srv.Addr.String(), grpc.WithInsecure())
			if err != nil {
				t.Fatalf("error opening gRPC client connection to fakekms: %v", err)
			}

			client, err := kms.NewKeyManagementClient(ctx, option.WithGRPCConn(clientConn))
			if err != nil {
				t.Fatalf("error creating KMS client: %v", err)
			}
			defer client.Close()

			kr, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
				Parent:    "projects/foo/locations/global",
				KeyRingId: uuid.NewString(),
			})
			if err != nil {
				t.Fatal(err)
			}

			ck, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
				Parent:      kr.Name,
				CryptoKeyId: uuid.NewString(),
				CryptoKey: &kmspb.CryptoKey{
					Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
					VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
						Algorithm:       test.kms_alg,
						ProtectionLevel: kmspb.ProtectionLevel_HSM,
					},
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			req := &kmspb.GetCryptoKeyVersionRequest{Name: ck.Name + "/cryptoKeyVersions/1"}
			ckv := &kmspb.CryptoKeyVersion{}
			for ckv.State != kmspb.CryptoKeyVersion_ENABLED {
				if ckv, err = client.GetCryptoKeyVersion(ctx, req); err != nil {
					t.Fatal(err)
				}
				time.Sleep(10 * time.Millisecond)
			}

			signer, err := gcpkms.NewSigner(ctx, client, ckv.Name)
			if err != nil {
				t.Fatal(err)
			}
			certFilePath := generateSelfSignedCertTempFile(t, signer, test.alg)
			defer os.Remove(certFilePath)

			// Copying notepad.exe to a temp file so that this test is idempotent.
			fileToSign, err := os.CreateTemp("", "signfile-*.exe")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(fileToSign.Name())
			notepadExe, err := os.Open("C:\\Windows\\notepad.exe")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(fileToSign, notepadExe); err != nil {
				t.Fatal(err)
			}
			fileToSign.Close() // signtool will open it

			cmd := exec.CommandContext(ctx, signtoolLocation(), "sign", "/v", "/debug",
				"/fd", test.sha, "/f", certFilePath, "/csp", "Google Cloud KMS Provider",
				"/kc", ckv.Name, fileToSign.Name())
			cmd.Env = []string{
				"KMS_ENDPOINT_ADDRESS=" + srv.Addr.String(),
				"KMS_CHANNEL_CREDENTIALS=insecure",
			}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("signtool command failed (%v):\n%s", err, string(out))
			}
		})
	}
}
