package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ValidateSignatureRequest Request Object
type ValidateSignatureRequest struct {
	Body *VerifyRequestBody `json:"body,omitempty"`
}

func (o ValidateSignatureRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ValidateSignatureRequest struct{}"
	}

	return strings.Join([]string{"ValidateSignatureRequest", string(data)}, " ")
}
