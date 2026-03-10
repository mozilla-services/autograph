package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/converter"

	"strings"
)

type EncryptDataRequestBody struct {

	// 密钥ID，36字节，满足正则匹配“^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$”。 例如：0d0466b0-e727-4d9c-b35d-f84bb474a37f。
	KeyId string `json:"key_id"`

	// 明文数据，1~4096字节，满足正则匹配“^.{1,4096}$”，且转化为byte数组后长度取值范围为1~4096字节。
	PlainText string `json:"plain_text"`

	// 数据加密算法，仅使用非对称密钥需要指定该参数，默认值为“SYMMETRIC_DEFAULT”，合法枚举值如下：  - SYMMETRIC_DEFAULT  - RSAES_OAEP_SHA_256  - SM2_ENCRYPT
	EncryptionAlgorithm *EncryptDataRequestBodyEncryptionAlgorithm `json:"encryption_algorithm,omitempty"`

	// 身份验证的非敏感额外数据。任意字符串，长度不超过128字节。
	AdditionalAuthenticatedData *string `json:"additional_authenticated_data,omitempty"`

	// 请求消息序列号，36字节序列号。 例如：919c82d4-8046-4722-9094-35c3c6524cff
	Sequence *string `json:"sequence,omitempty"`
}

func (o EncryptDataRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "EncryptDataRequestBody struct{}"
	}

	return strings.Join([]string{"EncryptDataRequestBody", string(data)}, " ")
}

type EncryptDataRequestBodyEncryptionAlgorithm struct {
	value string
}

type EncryptDataRequestBodyEncryptionAlgorithmEnum struct {
	SYMMETRIC_DEFAULT  EncryptDataRequestBodyEncryptionAlgorithm
	RSAES_OAEP_SHA_256 EncryptDataRequestBodyEncryptionAlgorithm
	SM2_ENCRYPT        EncryptDataRequestBodyEncryptionAlgorithm
}

func GetEncryptDataRequestBodyEncryptionAlgorithmEnum() EncryptDataRequestBodyEncryptionAlgorithmEnum {
	return EncryptDataRequestBodyEncryptionAlgorithmEnum{
		SYMMETRIC_DEFAULT: EncryptDataRequestBodyEncryptionAlgorithm{
			value: "SYMMETRIC_DEFAULT",
		},
		RSAES_OAEP_SHA_256: EncryptDataRequestBodyEncryptionAlgorithm{
			value: "RSAES_OAEP_SHA_256",
		},
		SM2_ENCRYPT: EncryptDataRequestBodyEncryptionAlgorithm{
			value: "SM2_ENCRYPT",
		},
	}
}

func (c EncryptDataRequestBodyEncryptionAlgorithm) Value() string {
	return c.value
}

func (c EncryptDataRequestBodyEncryptionAlgorithm) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *EncryptDataRequestBodyEncryptionAlgorithm) UnmarshalJSON(b []byte) error {
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
