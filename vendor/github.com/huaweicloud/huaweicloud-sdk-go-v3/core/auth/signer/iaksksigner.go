// Copyright 2023 Huawei Technologies Co.,Ltd.
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

package signer

import (
	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/signer/algorithm"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/request"
)

type IAKSKSigner interface {
	Sign(req *request.DefaultHttpRequest, ak, sk string) (map[string]string, error)
}

func GetSigner(alg algorithm.SigningAlgorithm) (IAKSKSigner, error) {
	var sig IAKSKSigner
	var err error
	switch alg {
	case algorithm.HmacSHA256:
		sig = signerInst
	case algorithm.HmacSM3:
		sig = sm3SignerInst
	case algorithm.EcdsaP256SHA256:
		sig = p256sha256SignerInst
	case algorithm.SM2SM3:
		sig = sm2sm3SignerInst
	default:
		err = errors.New("unsupported signing algorithm: " + string(alg))
	}

	if err != nil {
		return nil, err
	}
	if sig == nil {
		return nil, errors.New("signing algorithm is nil")
	}
	return sig, nil
}
