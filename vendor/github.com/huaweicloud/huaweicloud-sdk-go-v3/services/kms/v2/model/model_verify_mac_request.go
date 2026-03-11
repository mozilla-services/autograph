package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// VerifyMacRequest Request Object
type VerifyMacRequest struct {
	Body *VerifyMacRequestBody `json:"body,omitempty"`
}

func (o VerifyMacRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "VerifyMacRequest struct{}"
	}

	return strings.Join([]string{"VerifyMacRequest", string(data)}, " ")
}
