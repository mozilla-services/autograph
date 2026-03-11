package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// EncryptDatakeyResponse Response Object
type EncryptDatakeyResponse struct {

	// 密钥ID
	KeyId *string `json:"key_id,omitempty"`

	// DEK密文16进制，两位表示1byte。
	CipherText *string `json:"cipher_text,omitempty"`

	// DEK字节长度。
	DatakeyLength  *string `json:"datakey_length,omitempty"`
	HttpStatusCode int     `json:"-"`
}

func (o EncryptDatakeyResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "EncryptDatakeyResponse struct{}"
	}

	return strings.Join([]string{"EncryptDatakeyResponse", string(data)}, " ")
}
