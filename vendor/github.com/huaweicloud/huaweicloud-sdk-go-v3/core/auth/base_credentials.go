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

package auth

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/internal"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/signer"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/impl"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/request"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/sdkerr"
	"time"
)

const (
	securityTokenInHeader             = "X-Security-Token"
	emptyAk                           = "EMPTY_AK"
	emptySK                           = "EMPTY_SK"
	defaultExpirationThresholdSeconds = 40 * 60 // 40min
)

var DefaultDerivedPredicate = GetDefaultDerivedPredicate()

type BaseCredentials struct {
	IamEndpoint      string
	AK               string
	SK               string
	SecurityToken    string
	IdpId            string
	IdTokenFile      string
	DerivedPredicate func(*request.DefaultHttpRequest) bool
	StsAccessor      internal.StsAccessor

	derivedAuthServiceName string
	regionId               string
	expireAt               int64
}

func (s *BaseCredentials) IsDerivedAuth(httpRequest *request.DefaultHttpRequest) bool {
	if s.DerivedPredicate == nil {
		return false
	}

	return s.DerivedPredicate(httpRequest)
}

func (s *BaseCredentials) isExpired() bool {
	return s.expireAt-time.Now().Unix() < defaultExpirationThresholdSeconds
}

func (s *BaseCredentials) needRefreshSts() bool {
	return s.StsAccessor != nil && s.isExpired()
}

func (s *BaseCredentials) ProcessSts(client *impl.DefaultHttpClient) error {
	if s.needRefreshSts() {
		iamEndpoint := s.IamEndpoint
		if iamEndpoint == "" {
			iamEndpoint = internal.GetIamEndpoint()
		}

		cred, err := s.StsAccessor.GetCredential(
			internal.WithClient(client),
			internal.WithIamEndpoint(iamEndpoint),
			internal.WithIdpId(s.IdpId),
			internal.WithIdTokenFile(s.IdTokenFile),
		)
		if err != nil {
			return err
		}

		s.AK = cred.Access
		s.SK = cred.Secret
		s.SecurityToken = cred.SecurityToken
		s.expireAt = cred.ExpireAt
	}
	return nil
}

func (s *BaseCredentials) selectIamEndpoint(regionId string) string {
	if s.IamEndpoint != "" {
		return s.IamEndpoint
	}

	return internal.GetIamEndpointById(regionId)
}

func (s *BaseCredentials) baseProcessAuthRequest(reqBuilder *request.HttpRequestBuilder, req *request.DefaultHttpRequest) error {
	if s.SecurityToken != "" {
		reqBuilder.AddHeaderParam(securityTokenInHeader, s.SecurityToken)
	}

	var additionalHeaders map[string]string
	var err error
	if s.IsDerivedAuth(req) {
		additionalHeaders, err = signer.GetDerivedSigner().Sign(reqBuilder.Build(), s.AK, s.SK, s.derivedAuthServiceName, s.regionId)
		if err != nil {
			return err
		}
	} else {
		sn, err := signer.GetSigner(req.GetSigningAlgorithm())
		if err != nil {
			return err
		}
		additionalHeaders, err = sn.Sign(reqBuilder.Build(), s.AK, s.SK)
		if err != nil {
			return err
		}
	}

	for key, value := range additionalHeaders {
		req.AddHeaderParam(key, value)
	}

	return nil
}

type BaseCredentialsBuilder struct {
	BaseCredentials *BaseCredentials
	errMap          map[string]string
}

func NewBaseCredentialsBuilder() *BaseCredentialsBuilder {
	return &BaseCredentialsBuilder{
		BaseCredentials: &BaseCredentials{},
		errMap:          make(map[string]string),
	}
}

func (builder *BaseCredentialsBuilder) WithIamEndpointOverride(endpoint string) *BaseCredentialsBuilder {
	builder.BaseCredentials.IamEndpoint = endpoint
	return builder
}

func (builder *BaseCredentialsBuilder) WithAk(ak string) *BaseCredentialsBuilder {
	if ak == "" {
		builder.errMap[emptyAk] = "input ak cannot be an empty string"
	} else {
		builder.BaseCredentials.AK = ak
		delete(builder.errMap, emptyAk)
	}
	return builder
}

func (builder *BaseCredentialsBuilder) WithSk(sk string) *BaseCredentialsBuilder {
	if sk == "" {
		builder.errMap[emptySK] = "input sk cannot be an empty string"
	} else {
		builder.BaseCredentials.SK = sk
		delete(builder.errMap, emptySK)
	}
	return builder
}

func (builder *BaseCredentialsBuilder) WithSecurityToken(token string) *BaseCredentialsBuilder {
	builder.BaseCredentials.SecurityToken = token
	return builder
}

func (builder *BaseCredentialsBuilder) WithDerivedPredicate(derivedPredicate func(*request.DefaultHttpRequest) bool) *BaseCredentialsBuilder {
	builder.BaseCredentials.DerivedPredicate = derivedPredicate
	return builder
}

func (builder *BaseCredentialsBuilder) WithIdpId(idpId string) *BaseCredentialsBuilder {
	builder.BaseCredentials.IdpId = idpId
	return builder
}

func (builder *BaseCredentialsBuilder) WithIdTokenFile(idTokenFile string) *BaseCredentialsBuilder {
	builder.BaseCredentials.IdTokenFile = idTokenFile
	return builder
}

func (builder *BaseCredentialsBuilder) WithStsAccessor(accessor internal.StsAccessor) *BaseCredentialsBuilder {
	builder.BaseCredentials.StsAccessor = accessor
	return builder
}

// Deprecated: This function may panic under certain circumstances. Use SafeBuild instead.
func (builder *BaseCredentialsBuilder) Build() *BaseCredentials {
	credentials, err := builder.SafeBuild()
	if err != nil {
		panic(err)
	}
	return credentials
}

func (builder *BaseCredentialsBuilder) SafeBuild() (*BaseCredentials, error) {
	if builder.errMap != nil && len(builder.errMap) != 0 {
		errMsg := "build credentials failed: "
		for _, msg := range builder.errMap {
			errMsg += msg + "; "
		}
		return nil, sdkerr.NewCredentialsTypeError(errMsg)
	}

	if builder.BaseCredentials.IdpId != "" || builder.BaseCredentials.IdTokenFile != "" {
		if builder.BaseCredentials.IdpId == "" {
			return nil, sdkerr.NewCredentialsTypeError("IdpId is required when using IdpId&IdTokenFile")
		}
		if builder.BaseCredentials.IdTokenFile == "" {
			return nil, sdkerr.NewCredentialsTypeError("IdTokenFile is required when using IdpId&IdTokenFile")
		}
		if builder.BaseCredentials.StsAccessor == nil {
			builder.BaseCredentials.StsAccessor = internal.NewFederalAccessor()
		}
	}

	// Compatibility for metadata processing: NewCredentialsBuilder().SafeBuild()
	if builder.BaseCredentials.AK == "" && builder.BaseCredentials.SK == "" && builder.BaseCredentials.StsAccessor == nil {
		builder.BaseCredentials.StsAccessor = internal.NewMetadataAccessor()
	}

	return builder.BaseCredentials, nil
}
