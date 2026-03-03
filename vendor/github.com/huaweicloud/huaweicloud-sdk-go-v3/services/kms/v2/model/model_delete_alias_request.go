package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// DeleteAliasRequest Request Object
type DeleteAliasRequest struct {
	Body *DeleteAliasRequestBody `json:"body,omitempty"`
}

func (o DeleteAliasRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "DeleteAliasRequest struct{}"
	}

	return strings.Join([]string{"DeleteAliasRequest", string(data)}, " ")
}
