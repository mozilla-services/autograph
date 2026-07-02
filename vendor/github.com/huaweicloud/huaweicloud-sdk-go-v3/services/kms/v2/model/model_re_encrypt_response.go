package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ReEncryptResponse Response Object
type ReEncryptResponse struct {

	// 重新加密时使用的密钥ID
	KeyId *string `json:"key_id,omitempty"`

	// 加密原密文时使用的密钥ID
	SourceKeyId *string `json:"source_key_id,omitempty"`

	// 原密文加密时使用的加密算法
	SourceEncryptionAlgorithm *string `json:"source_encryption_algorithm,omitempty"`

	// 重新加密时使用的加密算法
	DestinationEncryptionAlgorithm *string `json:"destination_encryption_algorithm,omitempty"`

	// 重新加密后的密文
	CipherText     *string `json:"cipher_text,omitempty"`
	HttpStatusCode int     `json:"-"`
}

func (o ReEncryptResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ReEncryptResponse struct{}"
	}

	return strings.Join([]string{"ReEncryptResponse", string(data)}, " ")
}
