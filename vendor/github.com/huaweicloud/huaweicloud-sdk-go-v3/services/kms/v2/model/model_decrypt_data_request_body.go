package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/converter"

	"strings"
)

type DecryptDataRequestBody struct {

	// 被加密数据密文。取值为加密数据结果中的cipher_text的值，满足正则匹配“^[0-9a-zA-Z+/=]{128,5648}$”。
	CipherText string `json:"cipher_text"`

	// 数据加密算法，仅使用非对称密钥需要指定该参数，默认值为“SYMMETRIC_DEFAULT”，合法枚举值如下：  - SYMMETRIC_DEFAULT  - RSAES_OAEP_SHA_256  - SM2_ENCRYPT
	EncryptionAlgorithm *DecryptDataRequestBodyEncryptionAlgorithm `json:"encryption_algorithm,omitempty"`

	// 密钥ID，36字节，满足正则匹配“^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$”。仅当密文使用非对称密钥加密时才需要此参数。 例如：0d0466b0-e727-4d9c-b35d-f84bb474a37f。
	KeyId *string `json:"key_id,omitempty"`

	// 身份验证的非敏感额外数据。任意字符串，长度不超过128字节。
	AdditionalAuthenticatedData *string `json:"additional_authenticated_data,omitempty"`

	// 请求消息序列号，36字节序列号。 例如：919c82d4-8046-4722-9094-35c3c6524cff
	Sequence *string `json:"sequence,omitempty"`
}

func (o DecryptDataRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "DecryptDataRequestBody struct{}"
	}

	return strings.Join([]string{"DecryptDataRequestBody", string(data)}, " ")
}

type DecryptDataRequestBodyEncryptionAlgorithm struct {
	value string
}

type DecryptDataRequestBodyEncryptionAlgorithmEnum struct {
	SYMMETRIC_DEFAULT  DecryptDataRequestBodyEncryptionAlgorithm
	RSAES_OAEP_SHA_256 DecryptDataRequestBodyEncryptionAlgorithm
	SM2_ENCRYPT        DecryptDataRequestBodyEncryptionAlgorithm
}

func GetDecryptDataRequestBodyEncryptionAlgorithmEnum() DecryptDataRequestBodyEncryptionAlgorithmEnum {
	return DecryptDataRequestBodyEncryptionAlgorithmEnum{
		SYMMETRIC_DEFAULT: DecryptDataRequestBodyEncryptionAlgorithm{
			value: "SYMMETRIC_DEFAULT",
		},
		RSAES_OAEP_SHA_256: DecryptDataRequestBodyEncryptionAlgorithm{
			value: "RSAES_OAEP_SHA_256",
		},
		SM2_ENCRYPT: DecryptDataRequestBodyEncryptionAlgorithm{
			value: "SM2_ENCRYPT",
		},
	}
}

func (c DecryptDataRequestBodyEncryptionAlgorithm) Value() string {
	return c.value
}

func (c DecryptDataRequestBodyEncryptionAlgorithm) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *DecryptDataRequestBodyEncryptionAlgorithm) UnmarshalJSON(b []byte) error {
	myConverter := converter.StringConverterFactory("string")
	if myConverter == nil {
		return errors.New("unsupported StringConverter type: string")
	}

	interf, err := myConverter.CovertStringToInterface(strings.Trim(string(b[:]), "\""))
	if err != nil {
		return err
	}

	if val, ok := interf.(string); ok {
		c.value = val
		return nil
	} else {
		return errors.New("convert enum data to string error")
	}
}
