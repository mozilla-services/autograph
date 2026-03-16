package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ShowKeyRotationStatusRequest Request Object
type ShowKeyRotationStatusRequest struct {
	Body *OperateKeyRequestBody `json:"body,omitempty"`
}

func (o ShowKeyRotationStatusRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ShowKeyRotationStatusRequest struct{}"
	}

	return strings.Join([]string{"ShowKeyRotationStatusRequest", string(data)}, " ")
}
