package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ShowPublicKeyRequest Request Object
type ShowPublicKeyRequest struct {
	Body *OperateKeyRequestBody `json:"body,omitempty"`
}

func (o ShowPublicKeyRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ShowPublicKeyRequest struct{}"
	}

	return strings.Join([]string{"ShowPublicKeyRequest", string(data)}, " ")
}
