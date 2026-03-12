package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// CreateGrantRequest Request Object
type CreateGrantRequest struct {
	Body *CreateGrantRequestBody `json:"body,omitempty"`
}

func (o CreateGrantRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CreateGrantRequest struct{}"
	}

	return strings.Join([]string{"CreateGrantRequest", string(data)}, " ")
}
