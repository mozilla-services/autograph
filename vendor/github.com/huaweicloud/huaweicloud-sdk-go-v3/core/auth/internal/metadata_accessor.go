// Copyright 2022 Huawei Technologies Co.,Ltd.
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
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/sdkerr"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MetadataEndpoint                = "http://169.254.169.254"
	GetTokenPath                    = "/meta-data/latest/api/token"
	GetSecurityKeyPath              = "/openstack/latest/securitykey"
	XMetadataToken                  = "X-Metadata-Token"
	XMetadataTokenTTLSeconds        = "X-Metadata-Token-Ttl-Seconds"
	ConfigAgencyError               = "Please configure Cloud Service Agency first"
	DefaultTokenTTLSeconds          = 6 * 60 * 60  // 6h
	DefaultCheckTokenDurationSecond = 24 * 60 * 60 // 24h
)

var (
	clientOnce sync.Once
	client     *http.Client
)

func getClient() *http.Client {
	clientOnce.Do(func() {
		client = &http.Client{Timeout: 3 * time.Second}
	})
	return client
}

type SimpleResponse struct {
	Status int
	Body   string
}

func execute(req *http.Request) (*SimpleResponse, error) {
	resp, err := getClient().Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &SimpleResponse{Status: resp.StatusCode, Body: string(body)}, nil
}

type MetadataAccessor struct {
	lastCallSeconds *int64
	token           *string
}

func NewMetadataAccessor() *MetadataAccessor {
	return &MetadataAccessor{}
}

func (m *MetadataAccessor) getToken() (*SimpleResponse, error) {
	url := MetadataEndpoint + GetTokenPath
	req, err := http.NewRequest(http.MethodPut, url, http.NoBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set(XMetadataTokenTTLSeconds, strconv.Itoa(DefaultTokenTTLSeconds))
	return execute(req)
}

func (m *MetadataAccessor) tryUpdateToken(returnErr bool) error {
	now := time.Now().Unix()
	m.lastCallSeconds = &now
	resp, err := m.getToken()
	if err != nil {
		return err
	}

	errFunc := func() error {
		return &sdkerr.ServiceResponseError{
			StatusCode:   resp.Status,
			ErrorMessage: resp.Body,
		}
	}

	switch resp.Status {
	case 200:
		m.token = &resp.Body
		return nil
	case 404, 405, 503:
		if returnErr {
			return errFunc()
		}
		m.token = nil
		return nil
	default:
		return errFunc()
	}
}

func (m *MetadataAccessor) GetCredentials() (*Credential, error) {
	if m.token == nil &&
		(m.lastCallSeconds == nil || time.Now().Unix()-*m.lastCallSeconds > DefaultCheckTokenDurationSecond) {
		err := m.tryUpdateToken(false)
		if err != nil {
			return nil, err
		}
	}

	url := MetadataEndpoint + GetSecurityKeyPath
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	if m.token != nil {
		req.Header.Set(XMetadataToken, *m.token)
	}
	resp, err := execute(req)
	if err != nil {
		return nil, err
	}

	if resp.Status == 401 && !strings.Contains(resp.Body, ConfigAgencyError) {
		err = m.tryUpdateToken(true)
		if err != nil {
			return nil, err
		}
		req.Header.Set(XMetadataToken, *m.token)
		resp, err = execute(req)
		if err != nil {
			return nil, err
		}
	}

	if resp.Status >= 400 {
		return nil, &sdkerr.ServiceResponseError{
			StatusCode:   resp.Status,
			ErrorMessage: resp.Body,
		}
	}

	respModel := &GetTemporaryCredentialFromMetadataResponse{}
	err = utils.Unmarshal([]byte(resp.Body), respModel)
	if err != nil {
		return nil, err
	}
	return respModel.Credential, nil

}
