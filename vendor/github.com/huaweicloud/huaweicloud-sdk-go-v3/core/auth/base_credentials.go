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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	securityTokenInHeader             = "X-Security-Token"
	emptyAk                           = "EMPTY_AK"
	emptySK                           = "EMPTY_SK"
	defaultExpirationThresholdSeconds = 40 * 60     // 40min
	defaultDurationSeconds            = 6 * 60 * 60 // 6h
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
	MetadataAccessor *internal.MetadataAccessor

	derivedAuthServiceName string
	regionId               string
	expiredAt              int64
}

func (s *BaseCredentials) IsDerivedAuth(httpRequest *request.DefaultHttpRequest) bool {
	if s.DerivedPredicate == nil {
		return false
	}

	return s.DerivedPredicate(httpRequest)
}

func (s *BaseCredentials) needUpdateSecurityTokenFromMetadata() bool {
	if s.AK == "" && s.SK == "" {
		return true
	}
	if s.expiredAt == 0 || s.SecurityToken == "" {
		return false
	}
	return s.expiredAt-time.Now().Unix() < defaultExpirationThresholdSeconds
}

func (s *BaseCredentials) getIdToken() (string, error) {
	file := filepath.Clean(s.IdTokenFile)
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
		return "", sdkerr.NewCredentialsTypeError("id token is empty")
	}
	return idToken, nil
}

func (s *BaseCredentials) UpdateSecurityTokenFromMetadata() error {
	if s.MetadataAccessor == nil {
		s.MetadataAccessor = internal.NewMetadataAccessor()
	}
	credential, err := s.MetadataAccessor.GetCredentials()
	if err != nil {
		return err
	}

	s.AK = credential.Access
	s.SK = credential.Secret
	s.SecurityToken = credential.Securitytoken
	location, err := time.ParseInLocation(`2006-01-02T15:04:05Z`, credential.ExpiresAt, time.UTC)
	if err != nil {
		return err
	}
	s.expiredAt = location.Unix()

	return nil
}

func (s *BaseCredentials) needUpdateFederalAuthToken() bool {
	if s.IdpId == "" || s.IdTokenFile == "" {
		return false
	}
	if s.SecurityToken == "" || s.expiredAt == 0 {
		return true
	}
	return s.expiredAt-time.Now().Unix() < defaultExpirationThresholdSeconds
}

func (s *BaseCredentials) updateAuthTokenByIdToken(client *impl.DefaultHttpClient) error {
	idToken, err := s.getIdToken()
	if err != nil {
		return err
	}

	var iamEndpoint string
	if s.IamEndpoint != "" {
		iamEndpoint = s.IamEndpoint
	} else {
		iamEndpoint = internal.GetIamEndpoint()
	}
	req := internal.GetUnscopedTokenWithIdTokenRequest(iamEndpoint, s.IdpId, idToken, client.GetHttpConfig())
	resp, err := internal.CreateTokenWithIdToken(client, req)
	if err != nil {
		return err
	}

	akReq := internal.GetCreateTemporaryAccessKeyByTokenRequest(iamEndpoint, resp.XSubjectToken, defaultDurationSeconds, client.GetHttpConfig())
	akResp, err := internal.CreateTemporaryAccessKeyByToken(client, akReq)
	if err != nil {
		return err
	}

	location, err := time.ParseInLocation(`2006-01-02T15:04:05Z`, akResp.Credential.ExpiresAt, time.UTC)
	if err != nil {
		return err
	}
	s.expiredAt = location.Unix()
	s.SecurityToken = akResp.Credential.Securitytoken
	s.AK = akResp.Credential.Access
	s.SK = akResp.Credential.Secret
	return nil
}

func (s *BaseCredentials) selectIamEndpoint(regionId string) string {
	if s.IamEndpoint != "" {
		return s.IamEndpoint
	}

	return internal.GetIamEndpointById(regionId)
}

func (s *BaseCredentials) refresh(client *impl.DefaultHttpClient) error {
	if s.needUpdateFederalAuthToken() {
		return s.updateAuthTokenByIdToken(client)
	}
	if s.needUpdateSecurityTokenFromMetadata() {
		return s.UpdateSecurityTokenFromMetadata()
	}
	return nil
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
	}
	return builder.BaseCredentials, nil
}
