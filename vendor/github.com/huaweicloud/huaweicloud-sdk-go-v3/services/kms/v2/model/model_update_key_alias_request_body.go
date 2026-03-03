package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

type UpdateKeyAliasRequestBody struct {

	// 密钥ID，36字节，满足正则匹配“^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$”。 例如：0d0466b0-e727-4d9c-b35d-f84bb474a37f。
	KeyId string `json:"key_id"`

	// 非默认主密钥别名，取值1到255字符，满足正则匹配“^[a-zA-Z0-9:/_-]{1,255}$”且 后缀不可以为“/default”。
	KeyAlias string `json:"key_alias"`

	// 请求消息序列号，36字节序列号。 例如：919c82d4-8046-4722-9094-35c3c6524cff
	Sequence *string `json:"sequence,omitempty"`
}

func (o UpdateKeyAliasRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "UpdateKeyAliasRequestBody struct{}"
	}

	return strings.Join([]string{"UpdateKeyAliasRequestBody", string(data)}, " ")
}
