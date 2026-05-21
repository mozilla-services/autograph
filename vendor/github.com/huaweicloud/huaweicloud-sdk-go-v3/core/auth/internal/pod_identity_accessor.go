package internal

import (
	"bytes"
	"fmt"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"
	"io/ioutil"
	"net/http"
	"time"
)

const podIdentityErrMsg = "failed to get credential from PodIdentityAccessor"

func NewPodIdentityAccessor(uri, file string) *PodIdentityAccessor {
	return &PodIdentityAccessor{
		uri:  uri,
		file: file,
	}
}

type PodIdentityAccessor struct {
	uri  string
	file string
}

func (p *PodIdentityAccessor) GetCredential(options ...StsAccessorOption) (*Credential, error) {
	token, err := getContent(p.file)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", p.uri, bytes.NewBuffer([]byte("{}")))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", podIdentityErrMsg, err)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", podIdentityErrMsg, err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %s", podIdentityErrMsg, string(b))
	}

	respModel := &AssumeAgencyForPodIdentityResponse{}
	err = utils.Unmarshal(b, respModel)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", podIdentityErrMsg, err)
	}
	return respModel.Credentials, nil
}
