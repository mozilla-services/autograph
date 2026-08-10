// Copyright 2023 Google LLC
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

// The ec_p256_point_asn1_octet_string_gen command generates
// ec_p256_point_asn1_octet_string.der.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"log"
	"os"
)

func main() {
	pubBytes, err := os.ReadFile("ec_p256_public.der")
	if err != nil {
		log.Fatal(err)
	}

	pub, err := x509.ParsePKIXPublicKey(pubBytes)
	if err != nil {
		log.Fatal(err)
	}

	k, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("unexected public key type: %T", pub)
	}

	// point is in the form specified in ANSI X9.62 section 4.3.2.
	//
	// That literature calls this an "octet string", but beware: it is a
	// plain octet string (i.e., just bytes), not an ASN.1 TLV octet string.
	point := elliptic.Marshal(k.Curve, k.X, k.Y)

	asn1Point, err := asn1.Marshal(point)
	if err != nil {
		log.Fatal(err)
	}

	os.Stdout.Write(asn1Point)
}
