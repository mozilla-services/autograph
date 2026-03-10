package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ImportKeyMaterialRequest Request Object
type ImportKeyMaterialRequest struct {
	Body *ImportKeyMaterialRequestBody `json:"body,omitempty"`
}

func (o ImportKeyMaterialRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ImportKeyMaterialRequest struct{}"
	}

	return strings.Join([]string{"ImportKeyMaterialRequest", string(data)}, " ")
}
