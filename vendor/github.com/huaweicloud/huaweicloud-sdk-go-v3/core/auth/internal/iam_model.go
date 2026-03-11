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
	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/converter"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"
	"strings"
)

type IamResponse struct {
	TraceId string
}

type KeystoneListProjectsResponse struct {
	IamResponse
	Projects *[]ProjectResult `json:"projects,omitempty"`
}

type ProjectResult struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

type KeystoneListAuthDomainsResponse struct {
	IamResponse
	Domains *[]Domains `json:"domains,omitempty"`
}

type Domains struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

type CreateTokenWithIdTokenRequest struct {
	XIdpId string                 `json:"X-Idp-Id"`
	Body   *GetIdTokenRequestBody `json:"body,omitempty"`
}

type GetIdTokenRequestBody struct {
	Auth *GetIdTokenAuthParams `json:"auth"`
}

type GetIdTokenAuthParams struct {
	IdToken *GetIdTokenIdTokenBody `json:"id_token"`

	Scope *GetIdTokenIdScopeBody `json:"scope,omitempty"`
}

type GetIdTokenIdTokenBody struct {
	Id string `json:"id"`
}

type GetIdTokenIdScopeBody struct {
	Domain *GetIdTokenScopeDomainOrProjectBody `json:"domain,omitempty"`

	Project *GetIdTokenScopeDomainOrProjectBody `json:"project,omitempty"`
}

type GetIdTokenScopeDomainOrProjectBody struct {
	Id   *string `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
}

type CreateTokenWithIdTokenResponse struct {
	IamResponse
	Token          *ScopedTokenInfo `json:"token"`
	XSubjectToken  string           `json:"X-Subject-Token"`
	XRequestId     string           `json:"X-Request-Id"`
	HttpStatusCode int              `json:"-"`
}

type ScopedTokenInfo struct {
	ExpiresAt string                     `json:"expires_at"`
	Methods   []string                   `json:"methods"`
	IssuedAt  string                     `json:"issued_at"`
	User      *FederationUserBody        `json:"user"`
	Domain    *DomainInfo                `json:"domain,omitempty"`
	Project   *ProjectInfo               `json:"project,omitempty"`
	Roles     []ScopedTokenInfoRoles     `json:"roles"`
	Catalog   []UnscopedTokenInfoCatalog `json:"catalog"`
}

type FederationUserBody struct {
	OsFederation *OsFederationInfo `json:"OS-FEDERATION"`
	Domain       *DomainInfo       `json:"domain"`
	Id           *string           `json:"id,omitempty"`
	Name         *string           `json:"name,omitempty"`
}

type OsFederationInfo struct {
	IdentityProvider *IdpIdInfo      `json:"identity_provider"`
	Protocol         *ProtocolIdInfo `json:"protocol"`
	Groups           []interface{}   `json:"groups"`
}

type IdpIdInfo struct {
	Id string `json:"id"`
}

type ProtocolIdInfo struct {
	Id string `json:"id"`
}

type DomainInfo struct {
	Id   *string `json:"id,omitempty"`
	Name string  `json:"name"`
}

type ProjectInfo struct {
	Domain *DomainInfo `json:"domain,omitempty"`
	Id     *string     `json:"id,omitempty"`
	Name   string      `json:"name"`
}

type ScopedTokenInfoRoles struct {
	Id   *string `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
}

type UnscopedTokenInfoCatalog struct {
	Id        *string `json:"id,omitempty"`
	Interface *string `json:"interface,omitempty"`
	Region    *string `json:"region,omitempty"`
	RegionId  *string `json:"region_id,omitempty"`
	Url       *string `json:"url,omitempty"`
}

type CreateTemporaryAccessKeyByTokenRequest struct {
	Body *CreateTemporaryAccessKeyByTokenRequestBody `json:"body,omitempty"`
}

type CreateTemporaryAccessKeyByTokenRequestBody struct {
	Auth *TokenAuth `json:"auth"`
}

type CreateTemporaryAccessKeyByTokenResponse struct {
	IamResponse
	Credential *Credential `json:"credential,omitempty"`
}

type GetTemporaryCredentialFromMetadataResponse struct {
	Credential *Credential `json:"credential,omitempty"`
}

type Credential struct {
	ExpiresAt string `json:"expires_at"`

	Access string `json:"access"`

	Secret string `json:"secret"`

	Securitytoken string `json:"securitytoken"`
}

type TokenAuth struct {
	Identity *TokenAuthIdentity `json:"identity"`
}

type TokenAuthIdentity struct {
	Methods []TokenAuthIdentityMethods `json:"methods"`
	Token   *IdentityToken             `json:"token,omitempty"`
}

type IdentityToken struct {
	Id              *string `json:"id,omitempty"`
	DurationSeconds *int32  `json:"duration_seconds,omitempty"`
}

type TokenAuthIdentityMethods struct {
	value string
}

type TokenAuthIdentityMethodsEnum struct {
	TOKEN TokenAuthIdentityMethods
}

func GetTokenAuthIdentityMethodsEnum() TokenAuthIdentityMethodsEnum {
	return TokenAuthIdentityMethodsEnum{
		TOKEN: TokenAuthIdentityMethods{
			value: "token",
		},
	}
}

func (c *TokenAuthIdentityMethods) Value() string {
	return c.value
}

func (c *TokenAuthIdentityMethods) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *TokenAuthIdentityMethods) UnmarshalJSON(b []byte) error {
	myConverter := converter.StringConverterFactory("string")
	if myConverter == nil {
		return errors.New("unsupported StringConverter type: string")
	}

	interf, err := myConverter.CovertStringToInterface(strings.Trim(string(b[:]), "\""))
	if err != nil {
		return err
	}

	if val, ok := interf.(string); ok {
		c.value = val
		return nil
	} else {
		return errors.New("convert enum data to string error")
	}
}
