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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/config"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/impl"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/request"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/sdkerr"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"
	"log"
	"net"
	"os"
	"strings"
	"sync"
)

const (
	StsEndpointEnv       = "HUAWEICLOUD_SDK_STS_ENDPOINT"
	GetCallerIdentityUri = "/v5/caller-identity"
)

var (
	stsEndpointMap = map[string]string{}
	stsOnce        sync.Once
)

func updateStsEndpoints() {
	if err := json.Unmarshal([]byte(stsEndpoint), &stsEndpointMap); err != nil {
		log.Println("unmarshal sts endpoints file failed, ignored")
	}
}

func GetStsEndpointById(regionId string) string {
	if endpoint := os.Getenv(StsEndpointEnv); endpoint != "" {
		https := "https://"
		if !strings.HasPrefix(endpoint, https) {
			endpoint = https + endpoint
		}
		return endpoint
	}

	stsOnce.Do(updateStsEndpoints)
	return stsEndpointMap[regionId]
}

func GetCallerIdentityRequest(endpoint string, conf config.HttpConfig) *request.DefaultHttpRequest {
	return request.NewHttpRequestBuilder().
		WithEndpoint(endpoint).
		WithPath(GetCallerIdentityUri).
		WithMethod("GET").
		WithSigningAlgorithm(conf.SigningAlgorithm).
		Build()
}

func GetAccountIdFromCallerIdentity(client *impl.DefaultHttpClient, req *request.DefaultHttpRequest) (string, error) {
	failedMsg := fmt.Sprintf("failed to get domain id from %s", req.GetEndpoint())
	response, err := client.SyncInvokeHttp(req)
	if err != nil {
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) {
			return "", fmt.Errorf("%s: %w", failedMsg, dnsError)
		}
		return "", err
	}

	if response.GetStatusCode() == 404 {
		return "", fmt.Errorf("%s: %d, requestId: %s", failedMsg, response.GetStatusCode(), response.GetHeader("x-request-id"))
	}
	err = sdkerr.DefaultErrorHandler{}.HandleError(nil, response)
	if err != nil {
		return "", fmt.Errorf("%s: %w", failedMsg, err)
	}

	data, err := response.GetBodyAsBytes()
	if err != nil {
		return "", err
	}
	var result map[string]string
	err = utils.Unmarshal(data, &result)
	if err != nil {
		return "", fmt.Errorf("%s: %w", failedMsg, err)
	}

	if accountId, ok := result["account_id"]; ok {
		return accountId, nil
	}
	return "", fmt.Errorf("%s: account_id not found", failedMsg)
}
