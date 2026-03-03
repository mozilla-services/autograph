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
	"fmt"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/internal"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/impl"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/request"
)

const (
	domainIdInHeader = "X-Domain-Id"
	globalRegionId   = "globe"
)

type GlobalCredentials struct {
	BaseCredentials
	DomainId string
}

func (s *GlobalCredentials) ProcessAuthParams(client *impl.DefaultHttpClient, region string) (ICredential, error) {
	if s.DomainId != "" {
		return s, nil
	}

	cacheName := ""
	if s.AK != "" {
		cacheName = s.AK
	} else if s.IdpId != "" {
		cacheName = s.IdpId
	}
	if domainId, ok := getCache().get(cacheName); ok {
		s.DomainId = domainId
		return s, nil
	}

	derivedPredicate := s.DerivedPredicate
	s.DerivedPredicate = nil

	req, err := s.ProcessAuthRequest(client, internal.GetKeystoneListAuthDomainsRequest(s.selectIamEndpoint(region), client.GetHttpConfig()))
	if err != nil {
		return nil, fmt.Errorf("failed to get domain id automatically, %w", err)
	}
	resp, err := internal.KeystoneListAuthDomains(client, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain id automatically, %w", err)
	}
	var id string
	domains := *resp.Domains
	if len(domains) == 0 {
		err = fmt.Errorf("failed to get domain id automatically, X-IAM-Trace-Id=%s,"+
			" please confirm that you have 'iam:users:getUser' permission, or set domain id manually:"+
			" global.NewCredentialsBuilder().WithAk(ak).WithSk(sk).WithDomainId(domainId).SafeBuild()", resp.TraceId)
		if stsEndpoint := internal.GetStsEndpointById(region); stsEndpoint != "" {
			req, err = s.ProcessAuthRequest(client, internal.GetCallerIdentityRequest(stsEndpoint, client.GetHttpConfig()))
			if err != nil {
				return nil, err
			}
			id, err = internal.GetAccountIdFromCallerIdentity(client, req)
		}
		if err != nil {
			return nil, err
		}
	} else {
		id = domains[0].Id
	}

	s.DomainId = id
	if cacheName != "" {
		getCache().put(cacheName, id)
	}

	s.DerivedPredicate = derivedPredicate
	return s, nil
}

func (s *GlobalCredentials) ProcessAuthRequest(client *impl.DefaultHttpClient, req *request.DefaultHttpRequest) (*request.DefaultHttpRequest, error) {
	err := s.refresh(client)
	if err != nil {
		return nil, err
	}

	reqBuilder := req.Builder()
	if s.DomainId != "" {
		reqBuilder = reqBuilder.AddAutoFilledPathParam("domain_id", s.DomainId).AddHeaderParam(domainIdInHeader, s.DomainId)
	}

	err = s.baseProcessAuthRequest(reqBuilder, req)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func (s *GlobalCredentials) ProcessDerivedAuthParams(derivedAuthServiceName, regionId string) ICredential {
	if s.derivedAuthServiceName == "" {
		s.derivedAuthServiceName = derivedAuthServiceName
	}

	if s.regionId == "" {
		s.regionId = globalRegionId
	}

	return s
}

type GlobalCredentialsBuilder struct {
	Builder  *BaseCredentialsBuilder
	DomainId string
}

func NewGlobalCredentialsBuilder() *GlobalCredentialsBuilder {
	return &GlobalCredentialsBuilder{Builder: NewBaseCredentialsBuilder()}
}

func (b *GlobalCredentialsBuilder) WithDomainId(domainId string) *GlobalCredentialsBuilder {
	b.DomainId = domainId
	return b
}

func (b *GlobalCredentialsBuilder) WithIamEndpointOverride(endpoint string) *GlobalCredentialsBuilder {
	b.Builder.WithIamEndpointOverride(endpoint)
	return b
}

func (b *GlobalCredentialsBuilder) WithAk(ak string) *GlobalCredentialsBuilder {
	b.Builder.WithAk(ak)
	return b
}

func (b *GlobalCredentialsBuilder) WithSk(sk string) *GlobalCredentialsBuilder {
	b.Builder.WithSk(sk)
	return b
}

func (b *GlobalCredentialsBuilder) WithSecurityToken(token string) *GlobalCredentialsBuilder {
	b.Builder.WithSecurityToken(token)
	return b
}

func (b *GlobalCredentialsBuilder) WithDerivedPredicate(derivedPredicate func(*request.DefaultHttpRequest) bool) *GlobalCredentialsBuilder {
	b.Builder.WithDerivedPredicate(derivedPredicate)
	return b
}

func (b *GlobalCredentialsBuilder) WithIdpId(idpId string) *GlobalCredentialsBuilder {
	b.Builder.WithIdpId(idpId)
	return b
}

func (b *GlobalCredentialsBuilder) WithIdTokenFile(idTokenFile string) *GlobalCredentialsBuilder {
	b.Builder.WithIdTokenFile(idTokenFile)
	return b
}

// Deprecated: This function may panic under certain circumstances. Use SafeBuild instead.
func (b *GlobalCredentialsBuilder) Build() *GlobalCredentials {
	credentials := b.Builder.Build()
	return &GlobalCredentials{BaseCredentials: *credentials, DomainId: b.DomainId}
}

func (b *GlobalCredentialsBuilder) SafeBuild() (*GlobalCredentials, error) {
	credentials, err := b.Builder.SafeBuild()
	if err != nil {
		return nil, err
	}
	return &GlobalCredentials{BaseCredentials: *credentials, DomainId: b.DomainId}, nil
}
