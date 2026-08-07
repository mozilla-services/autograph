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

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"flag"
	"io/ioutil"
	"log"
	"os"
)

var (
	wrappedKeyFile  = flag.String("wrapped_key_file", "", "the path to a wrapped key file with IV prepended")
	wrappingKeyFile = flag.String("wrapping_key_file", "", "the path to a file that contains a wrapping key")
)

func unwrapKey(wrappingKeyFile, wrappedKeyFile string) ([]byte, error) {
	wrappingKey, err := ioutil.ReadFile(wrappingKeyFile)
	if err != nil {
		return nil, err
	}

	wrappedKey, err := ioutil.ReadFile(wrappedKeyFile)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, wrappedKey[:12], wrappedKey[12:], nil)
}

func main() {
	flag.Parse()

	if *wrappedKeyFile == "" {
		log.Fatal("--wrapped_key_file is required")
	}
	if *wrappingKeyFile == "" {
		log.Fatal("--wrapping_key_file is required")
	}

	b, err := unwrapKey(*wrappingKeyFile, *wrappedKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	os.Stdout.Write(b)
}
