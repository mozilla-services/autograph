package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ReEncryptRequest Request Object
type ReEncryptRequest struct {
	Body *ReEncryptRequestBody `json:"body,omitempty"`
}

func (o ReEncryptRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ReEncryptRequest struct{}"
	}

	return strings.Join([]string{"ReEncryptRequest", string(data)}, " ")
}
