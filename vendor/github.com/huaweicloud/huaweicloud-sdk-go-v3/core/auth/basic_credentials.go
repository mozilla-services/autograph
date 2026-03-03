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
	"strings"
)

const projectIdInHeader = "X-Project-Id"

type BasicCredentials struct {
	BaseCredentials
	ProjectId string
}

func (s *BasicCredentials) ProcessAuthParams(client *impl.DefaultHttpClient, region string) (ICredential, error) {
	if s.ProjectId != "" {
		return s, nil
	}

	cacheName := ""
	if s.AK != "" {
		cacheName = s.AK + region
	} else if s.IdpId != "" {
		cacheName = s.IdpId + region
	}

	if projectId, ok := getCache().get(cacheName); ok {
		s.ProjectId = projectId
		return s, nil
	}

	derivedPredicate := s.DerivedPredicate
	s.DerivedPredicate = nil

	r := internal.GetKeystoneListProjectsRequest(s.selectIamEndpoint(region), region, client.GetHttpConfig())
	req, err := s.ProcessAuthRequest(client, r)
	if err != nil {
		return nil, fmt.Errorf("failed to get project id of region '%s' automatically: %s", region, err.Error())
	}

	resp, err := internal.KeystoneListProjects(client, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get project id of region '%s' automatically, %s", region, err.Error())
	}
	projects := *resp.Projects
	if len(projects) < 1 {
		return nil, fmt.Errorf("failed to get project id of region '%s' automatically, X-IAM-Trace-Id=%s,"+
			" confirm that the project exists in your account, or set project id manually:"+
			" basic.NewCredentialsBuilder().WithAk(ak).WithSk(sk).WithProjectId(projectId).SafeBuild()", region, resp.TraceId)
	} else if len(projects) > 1 {
		projectIds := make([]string, 0, len(projects))
		for _, project := range projects {
			projectIds = append(projectIds, project.Id)
		}
		return nil, fmt.Errorf("multiple project ids found: [%s], X-IAM-Trace-Id=%s, please select one when initializing the credentials:"+
			" basic.NewCredentialsBuilder().WithAk(ak).WithSk(sk).WithProjectId(projectId).SafeBuild()", strings.Join(projectIds, ","), resp.TraceId)
	}

	id := projects[0].Id
	s.ProjectId = id
	if cacheName != "" {
		getCache().put(cacheName, id)
	}

	s.DerivedPredicate = derivedPredicate

	return s, nil
}

func (s *BasicCredentials) ProcessAuthRequest(client *impl.DefaultHttpClient, req *request.DefaultHttpRequest) (*request.DefaultHttpRequest, error) {
	err := s.refresh(client)
	if err != nil {
		return nil, err
	}

	reqBuilder := req.Builder()
	if s.ProjectId != "" {
		reqBuilder = reqBuilder.AddAutoFilledPathParam("project_id", s.ProjectId).AddHeaderParam(projectIdInHeader, s.ProjectId)
	}

	err = s.baseProcessAuthRequest(reqBuilder, req)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func (s *BasicCredentials) ProcessDerivedAuthParams(derivedAuthServiceName, regionId string) ICredential {
	if s.derivedAuthServiceName == "" {
		s.derivedAuthServiceName = derivedAuthServiceName
	}
	if s.regionId == "" {
		s.regionId = regionId
	}
	return s
}

type BasicCredentialsBuilder struct {
	Builder   *BaseCredentialsBuilder
	ProjectId string
}

func NewBasicCredentialsBuilder() *BasicCredentialsBuilder {
	return &BasicCredentialsBuilder{Builder: NewBaseCredentialsBuilder()}
}

func (b *BasicCredentialsBuilder) WithProjectId(projectId string) *BasicCredentialsBuilder {
	b.ProjectId = projectId
	return b
}

func (b *BasicCredentialsBuilder) WithIamEndpointOverride(endpoint string) *BasicCredentialsBuilder {
	b.Builder.WithIamEndpointOverride(endpoint)
	return b
}

func (b *BasicCredentialsBuilder) WithAk(ak string) *BasicCredentialsBuilder {
	b.Builder.WithAk(ak)
	return b
}

func (b *BasicCredentialsBuilder) WithSk(sk string) *BasicCredentialsBuilder {
	b.Builder.WithSk(sk)
	return b
}

func (b *BasicCredentialsBuilder) WithSecurityToken(token string) *BasicCredentialsBuilder {
	b.Builder.WithSecurityToken(token)
	return b
}

func (b *BasicCredentialsBuilder) WithDerivedPredicate(derivedPredicate func(*request.DefaultHttpRequest) bool) *BasicCredentialsBuilder {
	b.Builder.WithDerivedPredicate(derivedPredicate)
	return b
}

func (b *BasicCredentialsBuilder) WithIdpId(idpId string) *BasicCredentialsBuilder {
	b.Builder.WithIdpId(idpId)
	return b
}

func (b *BasicCredentialsBuilder) WithIdTokenFile(idTokenFile string) *BasicCredentialsBuilder {
	b.Builder.WithIdTokenFile(idTokenFile)
	return b
}

// Deprecated: This function may panic under certain circumstances. Use SafeBuild instead.
func (b *BasicCredentialsBuilder) Build() *BasicCredentials {
	credentials := b.Builder.Build()
	return &BasicCredentials{BaseCredentials: *credentials, ProjectId: b.ProjectId}
}

func (b *BasicCredentialsBuilder) SafeBuild() (*BasicCredentials, error) {
	credentials, err := b.Builder.SafeBuild()
	if err != nil {
		return nil, err
	}
	return &BasicCredentials{BaseCredentials: *credentials, ProjectId: b.ProjectId}, nil
}
