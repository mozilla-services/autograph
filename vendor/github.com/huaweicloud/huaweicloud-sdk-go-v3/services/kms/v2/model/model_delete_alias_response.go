package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// DeleteAliasResponse Response Object
type DeleteAliasResponse struct {
	HttpStatusCode int `json:"-"`
}

func (o DeleteAliasResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "DeleteAliasResponse struct{}"
	}

	return strings.Join([]string{"DeleteAliasResponse", string(data)}, " ")
}
