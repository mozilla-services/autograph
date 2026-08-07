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

package fakekms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"errors"
	"fmt"
)

//go:embed testdata/*.pem
var testdata embed.FS

type keyFactory interface {
	Generate() interface{}
}

type ecKeyFactory struct {
	curve elliptic.Curve
}

func (f *ecKeyFactory) Generate() interface{} {
	k, err := ecdsa.GenerateKey(f.curve, rand.Reader)
	if err != nil {
		panic(err) // we ran out of entropy
	}
	return k
}

type rsaKeyFactory int

func (f rsaKeyFactory) Generate() interface{} {
	key, err := func() (*rsa.PrivateKey, error) {
		pemKey, err := testdata.ReadFile(fmt.Sprintf("testdata/rsa_%d_private.pem", f))
		if err != nil {
			return nil, fmt.Errorf("unsupported RSA key size: %d", f)
		}
		block, _ := pem.Decode(pemKey)
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			return nil, errors.New("failed to decode PEM block containing RSA private key")
		}
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}()
	if err != nil {
		panic("error loading pregenerated RSA private key: " + err.Error())
	}
	return key
}

type symmetricKeyFactory int

func (f symmetricKeyFactory) Generate() interface{} {
	k := make([]byte, int(f)/8)
	if _, err := rand.Read(k); err != nil {
		panic(err) // we ran out of entropy
	}
	return k
}
