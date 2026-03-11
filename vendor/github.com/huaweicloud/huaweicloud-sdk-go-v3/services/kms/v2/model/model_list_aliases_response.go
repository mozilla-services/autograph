package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ListAliasesResponse Response Object
type ListAliasesResponse struct {
	Body           *[]ListAliasResponseBody `json:"body,omitempty"`
	HttpStatusCode int                      `json:"-"`
}

func (o ListAliasesResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ListAliasesResponse struct{}"
	}

	return strings.Join([]string{"ListAliasesResponse", string(data)}, " ")
}
