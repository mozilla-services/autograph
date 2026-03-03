package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ListAliasesRequest Request Object
type ListAliasesRequest struct {

	// 密钥ID
	KeyId *string `json:"key_id,omitempty"`

	// 指定查询返回记录条数
	Limit *string `json:"limit,omitempty"`

	// 分页查询起始位置标识
	Marker *string `json:"marker,omitempty"`
}

func (o ListAliasesRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ListAliasesRequest struct{}"
	}

	return strings.Join([]string{"ListAliasesRequest", string(data)}, " ")
}
