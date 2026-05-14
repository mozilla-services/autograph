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

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/impl"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/sdkerr"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultExpirationThresholdSeconds = 2 * 60 * 60 // 2h
)

type StsAccessorConfig struct {
	Client                          *impl.DefaultHttpClient
	IdpId, IdTokenFile, IamEndpoint string
}

type StsAccessorOption func(*StsAccessorConfig)

func WithClient(client *impl.DefaultHttpClient) StsAccessorOption {
	return func(config *StsAccessorConfig) {
		config.Client = client
	}
}

func WithIdpId(idpId string) StsAccessorOption {
	return func(config *StsAccessorConfig) {
		config.IdpId = idpId
	}
}

func WithIdTokenFile(idTokenFile string) StsAccessorOption {
	return func(config *StsAccessorConfig) {
		config.IdTokenFile = idTokenFile
	}
}

func WithIamEndpoint(iamEndpoint string) StsAccessorOption {
	return func(config *StsAccessorConfig) {
		config.IamEndpoint = iamEndpoint
	}
}

type StsAccessor interface {
	GetCredential(options ...StsAccessorOption) (*Credential, error)
}

func getContent(path string) (string, error) {
	file := filepath.Clean(path)
	_, err := os.Stat(file)
	if err != nil {
		return "", err
	}

	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		return "", err
	}
	idToken := strings.TrimSpace(string(bytes))
	if idToken == "" {
		return "", sdkerr.NewCredentialsTypeError(path + " file content is empty")
	}
	return idToken, nil
}
