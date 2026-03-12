package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// AssociateAliasRequestBody 关联别名请求消息体
type AssociateAliasRequestBody struct {

	// 待关联别名
	Alias string `json:"alias"`

	// 待关联的密钥ID
	TargetKeyId string `json:"target_key_id"`
}

func (o AssociateAliasRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "AssociateAliasRequestBody struct{}"
	}

	return strings.Join([]string{"AssociateAliasRequestBody", string(data)}, " ")
}
