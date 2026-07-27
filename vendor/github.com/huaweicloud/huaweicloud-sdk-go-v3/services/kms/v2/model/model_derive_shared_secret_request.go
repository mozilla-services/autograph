package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// DeriveSharedSecretRequest Request Object
type DeriveSharedSecretRequest struct {
	Body *DeriveSharedSecretRequestBody `json:"body,omitempty"`
}

func (o DeriveSharedSecretRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "DeriveSharedSecretRequest struct{}"
	}

	return strings.Join([]string{"DeriveSharedSecretRequest", string(data)}, " ")
}
