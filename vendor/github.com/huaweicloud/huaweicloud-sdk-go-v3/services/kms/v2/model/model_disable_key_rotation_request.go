package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// DisableKeyRotationRequest Request Object
type DisableKeyRotationRequest struct {
	Body *OperateKeyRequestBody `json:"body,omitempty"`
}

func (o DisableKeyRotationRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "DisableKeyRotationRequest struct{}"
	}

	return strings.Join([]string{"DisableKeyRotationRequest", string(data)}, " ")
}
