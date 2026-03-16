package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// CancelSelfGrantRequest Request Object
type CancelSelfGrantRequest struct {
	Body *RevokeGrantRequestBody `json:"body,omitempty"`
}

func (o CancelSelfGrantRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CancelSelfGrantRequest struct{}"
	}

	return strings.Join([]string{"CancelSelfGrantRequest", string(data)}, " ")
}
