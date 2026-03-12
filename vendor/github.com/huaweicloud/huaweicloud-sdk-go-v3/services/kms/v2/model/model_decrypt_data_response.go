package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// DecryptDataResponse Response Object
type DecryptDataResponse struct {

	// 密钥ID。
	KeyId *string `json:"key_id,omitempty"`

	// 明文。
	PlainText *string `json:"plain_text,omitempty"`

	// 明文的Base64值，在非对称加密场景下，若加密的明文中含有不可见字符，则解密结果以该值为准。
	PlainTextBase64 *string `json:"plain_text_base64,omitempty"`
	HttpStatusCode  int     `json:"-"`
}

func (o DecryptDataResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "DecryptDataResponse struct{}"
	}

	return strings.Join([]string{"DecryptDataResponse", string(data)}, " ")
}
