package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// Recipient 擎天机密计算请求体
type Recipient struct {

	// 擎天机密计算证明文档
	AttestationDocument *string `json:"attestation_document,omitempty"`

	// 指定加密算法，仅支持RSAES_OAEP_SHA_256
	KeyEncryptionAlgorithm *string `json:"key_encryption_algorithm,omitempty"`
}

func (o Recipient) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "Recipient struct{}"
	}

	return strings.Join([]string{"Recipient", string(data)}, " ")
}
