package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ListKeyDetailRequest Request Object
type ListKeyDetailRequest struct {
	Body *OperateKeyRequestBody `json:"body,omitempty"`
}

func (o ListKeyDetailRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ListKeyDetailRequest struct{}"
	}

	return strings.Join([]string{"ListKeyDetailRequest", string(data)}, " ")
}
