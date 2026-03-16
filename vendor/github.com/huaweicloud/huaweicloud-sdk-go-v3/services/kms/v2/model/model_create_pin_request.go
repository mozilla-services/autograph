package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// CreatePinRequest Request Object
type CreatePinRequest struct {
	Body *CreatePinRequestBody `json:"body,omitempty"`
}

func (o CreatePinRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CreatePinRequest struct{}"
	}

	return strings.Join([]string{"CreatePinRequest", string(data)}, " ")
}
