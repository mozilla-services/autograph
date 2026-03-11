package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

type CreateAliasRequestBody struct {

	// 密钥ID
	KeyId string `json:"key_id"`

	// 别名。一个账号在同一个区域别名不能重复
	Alias string `json:"alias"`
}

func (o CreateAliasRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CreateAliasRequestBody struct{}"
	}

	return strings.Join([]string{"CreateAliasRequestBody", string(data)}, " ")
}
