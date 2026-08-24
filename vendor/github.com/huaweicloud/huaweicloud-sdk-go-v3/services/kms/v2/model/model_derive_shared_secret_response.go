package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// DeriveSharedSecretResponse Response Object
type DeriveSharedSecretResponse struct {

	// 密钥ID
	KeyId *string `json:"key_id,omitempty"`

	// 密钥协商算法
	KeyAgreementAlgorithm *string `json:"key_agreement_algorithm,omitempty"`

	// 由KMS私钥和您的对端公钥协商出的密钥，Base64格式，如果响应体包含了ciphertext_recipient，则不会包含shared_secret
	SharedSecret *string `json:"shared_secret,omitempty"`

	// KMS私钥和您的对端公钥协商出的密钥经过擎天证明文档加密后的密文，密文仅能被机密环境中的私钥解密，指定擎天证明文档后，才会响应ciphertext_recipient，否则通过shared_secret响应明文的共享密钥
	CiphertextRecipient *string `json:"ciphertext_recipient,omitempty"`
	HttpStatusCode      int     `json:"-"`
}

func (o DeriveSharedSecretResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "DeriveSharedSecretResponse struct{}"
	}

	return strings.Join([]string{"DeriveSharedSecretResponse", string(data)}, " ")
}
