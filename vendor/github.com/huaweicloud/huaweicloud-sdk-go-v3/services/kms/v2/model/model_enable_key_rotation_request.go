package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// EnableKeyRotationRequest Request Object
type EnableKeyRotationRequest struct {
	Body *OperateKeyRequestBody `json:"body,omitempty"`
}

func (o EnableKeyRotationRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "EnableKeyRotationRequest struct{}"
	}

	return strings.Join([]string{"EnableKeyRotationRequest", string(data)}, " ")
}
