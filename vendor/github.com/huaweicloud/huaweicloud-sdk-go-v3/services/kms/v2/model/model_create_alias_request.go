package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// CreateAliasRequest Request Object
type CreateAliasRequest struct {
	Body *CreateAliasRequestBody `json:"body,omitempty"`
}

func (o CreateAliasRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CreateAliasRequest struct{}"
	}

	return strings.Join([]string{"CreateAliasRequest", string(data)}, " ")
}
