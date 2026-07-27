package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ReEncryptRequestBody 重加密的请求体
type ReEncryptRequestBody struct {

	// 原密钥ID，用于解密密文。对于非对称密钥加密的密文source_key_id必填。对于对称密钥加密的密文，推荐填写source_key_id。kms会优先使用您填写的source_key_id进行解密。不填时会尝试从密文中解析出加密时使用的密钥ID进行解密。
	SourceKeyId *string `json:"source_key_id,omitempty"`

	// 加密原密文时使用的aad信息。如果加密时，没指定aad，则不能填写，否则会造成解密失败
	SourceAdditionalAuthenticatedData *string `json:"source_additional_authenticated_data,omitempty"`

	// 加密原密文时使用的加密算法。默认值为“SYMMETRIC_DEFAULT”，合法枚举值如下： SYMMETRIC_DEFAULT RSAES_OAEP_SHA_1 RSAES_OAEP_SHA_256 SM2_ENCRYPT 注意：RSAES_OAEP_SHA_1已不再安全，请谨慎使用
	SourceEncryptionAlgorithm *string `json:"source_encryption_algorithm,omitempty"`

	// 目的密钥ID,用于加密解密后的明文
	DestinationKeyId string `json:"destination_key_id"`

	// 如果指定了值，会在重加密时，作为aad参与计算
	DestinationAdditionalAuthenticatedData *string `json:"destination_additional_authenticated_data,omitempty"`

	// 重加密新密文时使用的加密算法。默认值为“SYMMETRIC_DEFAULT”，合法枚举值如下： SYMMETRIC_DEFAULT RSAES_OAEP_SHA_1 RSAES_OAEP_SHA_256 SM2_ENCRYPT 注意：RSAES_OAEP_SHA_1已不再安全，请谨慎使用
	DestinationEncryptionAlgorithm *string `json:"destination_encryption_algorithm,omitempty"`

	// 当密文是CBC 模式加密的 数据密钥时，需要指定datakey_cipher_length。表示明文密钥材料的字节数
	DatakeyCipherLength *string `json:"datakey_cipher_length,omitempty"`

	// 需要进行重加密的密文。
	CipherText string `json:"cipher_text"`
}

func (o ReEncryptRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ReEncryptRequestBody struct{}"
	}

	return strings.Join([]string{"ReEncryptRequestBody", string(data)}, " ")
}
