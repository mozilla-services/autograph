// Copyright 2025 Huawei Technologies Co.,Ltd.
//
// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package hkdf

import (
	"crypto/hmac"
	"errors"
	"hash"
	"io"
)

type KeyDerivation struct {
	hashExpander hash.Hash
	hashSize     int
	context      []byte
	ctr          uint8
	previous     []byte
	cache        []byte
}

func (kd *KeyDerivation) Read(output []byte) (int, error) {
	totalNeeded := len(output)
	available := len(kd.cache) + int(255-kd.ctr+1)*kd.hashSize

	if available < totalNeeded {
		return 0, errors.New("hkdf: output limit exceeded")
	}

	copied := copy(output, kd.cache)
	output = output[copied:]

	for len(output) > 0 {
		kd.hashExpander.Reset()

		if _, err := kd.hashExpander.Write(kd.previous); err != nil {
			return 0, err
		}
		if _, err := kd.hashExpander.Write(kd.context); err != nil {
			return 0, err
		}
		if _, err := kd.hashExpander.Write([]byte{kd.ctr}); err != nil {
			return 0, err
		}

		kd.previous = kd.hashExpander.Sum(kd.previous[:0])
		kd.ctr++

		kd.cache = kd.previous
		copied = copy(output, kd.cache)
		output = output[copied:]
	}

	kd.cache = kd.cache[copied:]
	return totalNeeded, nil
}

func Extract(hashFunc func() hash.Hash, secret, salt []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, hashFunc().Size())
	}
	return extractKey(hashFunc, secret, salt)
}

func New(hashFunc func() hash.Hash, secret, salt, info []byte) io.Reader {
	if len(salt) == 0 {
		salt = make([]byte, hashFunc().Size())
	}

	prk := extractKey(hashFunc, secret, salt)
	return newExpander(hashFunc, prk, info)
}

func extractKey(hashFunc func() hash.Hash, secret, salt []byte) []byte {
	mac := hmac.New(hashFunc, salt)
	_, err := mac.Write(secret)
	if err != nil {
		return []byte{}
	}
	return mac.Sum(nil)
}

func newExpander(hashFunc func() hash.Hash, prk, info []byte) *KeyDerivation {
	expander := hmac.New(hashFunc, prk)
	return &KeyDerivation{
		hashExpander: expander,
		hashSize:     expander.Size(),
		context:      info,
		ctr:          1,
		previous:     nil,
		cache:        nil,
	}
}

func Expand(hashFunc func() hash.Hash, prk, info []byte) io.Reader {
	return newExpander(hashFunc, prk, info)
}
