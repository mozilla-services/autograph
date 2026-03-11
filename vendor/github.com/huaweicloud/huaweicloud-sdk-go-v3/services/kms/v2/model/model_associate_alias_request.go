package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// AssociateAliasRequest Request Object
type AssociateAliasRequest struct {
	Body *AssociateAliasRequestBody `json:"body,omitempty"`
}

func (o AssociateAliasRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "AssociateAliasRequest struct{}"
	}

	return strings.Join([]string{"AssociateAliasRequest", string(data)}, " ")
}
