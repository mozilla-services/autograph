package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// GenerateMacRequest Request Object
type GenerateMacRequest struct {
	Body *GenerateMacRequestBody `json:"body,omitempty"`
}

func (o GenerateMacRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "GenerateMacRequest struct{}"
	}

	return strings.Join([]string{"GenerateMacRequest", string(data)}, " ")
}
