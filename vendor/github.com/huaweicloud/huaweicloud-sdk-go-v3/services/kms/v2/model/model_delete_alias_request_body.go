package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// DeleteAliasRequestBody 删除别名请求消息体
type DeleteAliasRequestBody struct {

	// 待删除的别名
	Aliases []string `json:"aliases"`

	// 别名关联的密钥ID
	KeyId string `json:"key_id"`
}

func (o DeleteAliasRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "DeleteAliasRequestBody struct{}"
	}

	return strings.Join([]string{"DeleteAliasRequestBody", string(data)}, " ")
}
