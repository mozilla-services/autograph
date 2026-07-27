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

package internal

const defaultDurationSeconds = 6 * 60 * 60 // 6h

type FederalAccessor struct {
	expireAt int64
}

func NewFederalAccessor() *FederalAccessor {
	return &FederalAccessor{}
}

func (f *FederalAccessor) GetCredential(options ...StsAccessorOption) (*Credential, error) {
	config := &StsAccessorConfig{}
	for _, option := range options {
		option(config)
	}

	idToken, err := getContent(config.IdTokenFile)
	if err != nil {
		return nil, err
	}

	req := GetUnscopedTokenWithIdTokenRequest(config.IamEndpoint, config.IdpId, idToken, config.Client.GetHttpConfig())
	resp, err := CreateTokenWithIdToken(config.Client, req)
	if err != nil {
		return nil, err
	}

	akReq := GetCreateTemporaryAccessKeyByTokenRequest(config.IamEndpoint, resp.XSubjectToken, defaultDurationSeconds, config.Client.GetHttpConfig())
	akResp, err := CreateTemporaryAccessKeyByToken(config.Client, akReq)
	if err != nil {
		return nil, err
	}

	f.expireAt = akResp.Credential.ExpireAt
	return akResp.Credential, nil
}
