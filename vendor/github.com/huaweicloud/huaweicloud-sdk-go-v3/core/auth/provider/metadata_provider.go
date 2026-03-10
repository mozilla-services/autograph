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
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/internal"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/sdkerr"
	"strings"
)

type MetadataCredentialProvider struct {
	credentialType string
}

// NewMetadataCredentialProvider return a metadata credential provider
// Supported credential types: basic, global
func NewMetadataCredentialProvider(credentialType string) *MetadataCredentialProvider {
	return &MetadataCredentialProvider{credentialType: strings.ToLower(credentialType)}
}

// BasicCredentialMetadataProvider return a metadata provider for basic.Credentials
func BasicCredentialMetadataProvider() *MetadataBasicCredentialProvider {
	return &MetadataBasicCredentialProvider{}
}

// GlobalCredentialMetadataProvider return a metadata provider for global.Credentials
func GlobalCredentialMetadataProvider() *MetadataGlobalCredentialProvider {
	return &MetadataGlobalCredentialProvider{}
}

// GetCredentials get basic.Credentials or global.Credentials from the instance's metadata
func (p *MetadataCredentialProvider) GetCredentials() (auth.ICredential, error) {
	if p.credentialType == "" {
		return nil, sdkerr.NewCredentialsTypeError("credential type is empty")
	}

	if strings.HasPrefix(p.credentialType, basicCredentialType) {
		return BasicCredentialMetadataProvider().GetCredentials()
	} else if strings.HasPrefix(p.credentialType, globalCredentialType) {
		return GlobalCredentialMetadataProvider().GetCredentials()
	}

	return nil, sdkerr.NewCredentialsTypeError("unsupported credential type: " + p.credentialType)
}

type MetadataBasicCredentialProvider struct {
	ProjectId string
}

type MetadataGlobalCredentialProvider struct {
	DomainId string
}

func (p *MetadataBasicCredentialProvider) GetCredentials() (auth.ICredential, error) {
	builder := auth.NewBasicCredentialsBuilder()
	if p.ProjectId != "" {
		builder.WithProjectId(p.ProjectId)
	}
	credentials, err := builder.SafeBuild()
	if err != nil {
		return nil, err
	}
	credentials.MetadataAccessor = internal.NewMetadataAccessor()
	err = credentials.UpdateSecurityTokenFromMetadata()
	if err != nil {
		return nil, err
	}
	return credentials, nil
}

func (p *MetadataGlobalCredentialProvider) GetCredentials() (auth.ICredential, error) {
	builder := auth.NewGlobalCredentialsBuilder()
	if p.DomainId != "" {
		builder.WithDomainId(p.DomainId)
	}
	credentials, err := builder.SafeBuild()
	if err != nil {
		return nil, err
	}
	credentials.MetadataAccessor = internal.NewMetadataAccessor()
	err = credentials.UpdateSecurityTokenFromMetadata()
	if err != nil {
		return nil, err
	}
	return credentials, nil
}
