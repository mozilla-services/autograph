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

package provider

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/sdkerr"
)

const (
	basicCredentialType  = "basic"
	globalCredentialType = "global"
)

type ICredentialProvider interface {
	GetCredentials() (auth.ICredential, error)
}

type commonAttrs struct {
	ak            string
	sk            string
	securityToken string
	idpId         string
	idTokenFile   string
	iamEndpoint   string
}

func fillCommonAttrs(builder interface{}, attrs commonAttrs) error {
	var baseBuilder *auth.BaseCredentialsBuilder
	if b, ok := builder.(*auth.BasicCredentialsBuilder); ok {
		baseBuilder = b.Builder
	} else if b, ok := builder.(*auth.GlobalCredentialsBuilder); ok {
		baseBuilder = b.Builder
	}

	if baseBuilder == nil {
		return sdkerr.NewCredentialsTypeError("credential type error")
	}

	if attrs.iamEndpoint != "" {
		baseBuilder.WithIamEndpointOverride(attrs.iamEndpoint)
	}
	if attrs.idpId != "" && attrs.idTokenFile != "" {
		baseBuilder.WithIdpId(attrs.idpId).WithIdTokenFile(attrs.idTokenFile)
		return nil
	} else if attrs.ak != "" && attrs.sk != "" {
		baseBuilder.WithAk(attrs.ak).WithSk(attrs.sk).WithSecurityToken(attrs.securityToken)
		return nil
	}

	return sdkerr.NewCredentialsTypeError("AK&SK or IdpId&IdTokenFile does not exist")
}
