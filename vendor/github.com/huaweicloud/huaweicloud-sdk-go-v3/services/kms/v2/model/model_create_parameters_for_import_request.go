package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// CreateParametersForImportRequest Request Object
type CreateParametersForImportRequest struct {
	Body *GetParametersForImportRequestBody `json:"body,omitempty"`
}

func (o CreateParametersForImportRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CreateParametersForImportRequest struct{}"
	}

	return strings.Join([]string{"CreateParametersForImportRequest", string(data)}, " ")
}
