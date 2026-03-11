package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

type DecryptDatakeyRequestBody struct {

	// 密钥ID，36字节，满足正则匹配“^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$”。 例如：0d0466b0-e727-4d9c-b35d-f84bb474a37f。
	KeyId string `json:"key_id"`

	// DEK密文及元数据的16进制字符串。取值为加密数据密钥结果中的cipher_text的值。
	CipherText string `json:"cipher_text"`

	// 密钥字节长度，取值范围为1~1024。 密钥字节长度，取值为“64”。
	DatakeyCipherLength string `json:"datakey_cipher_length"`

	// 身份验证的非敏感额外数据。任意字符串，长度不超过128字节。
	AdditionalAuthenticatedData *string `json:"additional_authenticated_data,omitempty"`

	// 请求消息序列号，36字节序列号。 例如：919c82d4-8046-4722-9094-35c3c6524cff
	Sequence *string `json:"sequence,omitempty"`
}

func (o DecryptDatakeyRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "DecryptDatakeyRequestBody struct{}"
	}

	return strings.Join([]string{"DecryptDatakeyRequestBody", string(data)}, " ")
}
