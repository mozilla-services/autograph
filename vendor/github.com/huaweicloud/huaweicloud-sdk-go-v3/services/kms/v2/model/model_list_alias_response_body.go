package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ListAliasResponseBody 查询别名响应消息体
type ListAliasResponseBody struct {

	// 密钥关联的所有别名
	Aliases []AliasEntity `json:"aliases"`

	PageInfo *PageInfo `json:"page_info"`
}

func (o ListAliasResponseBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ListAliasResponseBody struct{}"
	}

	return strings.Join([]string{"ListAliasResponseBody", string(data)}, " ")
}
