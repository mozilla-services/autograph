package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// DeleteImportedKeyMaterialRequest Request Object
type DeleteImportedKeyMaterialRequest struct {
	Body *OperateKeyRequestBody `json:"body,omitempty"`
}

func (o DeleteImportedKeyMaterialRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "DeleteImportedKeyMaterialRequest struct{}"
	}

	return strings.Join([]string{"DeleteImportedKeyMaterialRequest", string(data)}, " ")
}
