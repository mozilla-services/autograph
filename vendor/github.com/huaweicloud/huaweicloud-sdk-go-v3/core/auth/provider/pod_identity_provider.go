package provider

import (
	"fmt"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/internal"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/sdkerr"
	"os"
	"strings"
)

const (
	hcContainerCredentialsFullUri     = "HC_CONTAINER_CREDENTIALS_FULL_URI"
	hcContainerAuthorizationTokenFile = "HC_CONTAINER_AUTHORIZATION_TOKEN_FILE"
)

func BasicCredentialPodIdentityProvider() *PodIdentityCredentialProvider {
	return &PodIdentityCredentialProvider{credentialType: basicCredentialType}
}

func GlobalCredentialPodIdentityProvider() *PodIdentityCredentialProvider {
	return &PodIdentityCredentialProvider{credentialType: globalCredentialType}
}

func NewPodIdentityCredentialProvider(credentialType string) *PodIdentityCredentialProvider {
	return &PodIdentityCredentialProvider{credentialType: credentialType}
}

type PodIdentityCredentialProvider struct {
	credentialType string
}

func (p *PodIdentityCredentialProvider) GetCredentials() (auth.ICredential, error) {
	uri := os.Getenv(hcContainerCredentialsFullUri)
	if uri == "" {
		return nil, fmt.Errorf("%s must be set when using pod identity credential", hcContainerCredentialsFullUri)
	}
	file := os.Getenv(hcContainerAuthorizationTokenFile)
	if file == "" {
		return nil, fmt.Errorf("%s must be set when using pod identity credential", hcContainerAuthorizationTokenFile)
	}

	accessor := internal.NewPodIdentityAccessor(uri, file)
	if strings.HasPrefix(p.credentialType, basicCredentialType) {
		credentials, err := auth.NewBasicCredentialsBuilder().WithStsAccessor(accessor).SafeBuild()
		if err != nil {
			return nil, err
		}
		err = credentials.ProcessSts(nil)
		if err != nil {
			return nil, err
		}
		return credentials, nil
	} else if strings.HasPrefix(p.credentialType, globalCredentialType) {
		credentials, err := auth.NewGlobalCredentialsBuilder().WithStsAccessor(accessor).SafeBuild()
		if err != nil {
			return nil, err
		}
		err = credentials.ProcessSts(nil)
		if err != nil {
			return nil, err
		}
		return credentials, nil
	}
	return nil, sdkerr.NewCredentialsTypeError("unsupported credential type: " + p.credentialType)
}
