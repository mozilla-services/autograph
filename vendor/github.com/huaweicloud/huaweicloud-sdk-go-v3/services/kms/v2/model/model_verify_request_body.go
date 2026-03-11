package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/converter"

	"strings"
)

type VerifyRequestBody struct {

	// 密钥ID，36字节，满足正则匹配“^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$”。 例如：0d0466b0-e727-4d9c-b35d-f84bb474a37f。
	KeyId string `json:"key_id"`

	// 待签名的消息摘要或者消息，消息长度要求小于4096字节，使用Base64编码。
	Message string `json:"message"`

	// 待验证的签名值，使用Base64编码。
	Signature string `json:"signature"`

	// 签名算法，枚举如下：  - RSASSA_PSS_SHA_256  - RSASSA_PSS_SHA_384  - RSASSA_PSS_SHA_512  - RSASSA_PKCS1_V1_5_SHA_256  - RSASSA_PKCS1_V1_5_SHA_384  - RSASSA_PKCS1_V1_5_SHA_512  - ECDSA_SHA_256  - ECDSA_SHA_384  - ECDSA_SHA_512  - SM2DSA_SM3
	SigningAlgorithm VerifyRequestBodySigningAlgorithm `json:"signing_algorithm"`

	// 消息类型，默认为“DIGEST”，枚举如下：  - DIGEST 表示消息摘要  - RAW 表示消息原文
	MessageType *VerifyRequestBodyMessageType `json:"message_type,omitempty"`

	// 请求消息序列号，36字节序列号。 例如：919c82d4-8046-4722-9094-35c3c6524cff。
	Sequence *string `json:"sequence,omitempty"`
}

func (o VerifyRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "VerifyRequestBody struct{}"
	}

	return strings.Join([]string{"VerifyRequestBody", string(data)}, " ")
}

type VerifyRequestBodySigningAlgorithm struct {
	value string
}

type VerifyRequestBodySigningAlgorithmEnum struct {
	RSASSA_PSS_SHA_256        VerifyRequestBodySigningAlgorithm
	RSASSA_PSS_SHA_384        VerifyRequestBodySigningAlgorithm
	RSASSA_PSS_SHA_512        VerifyRequestBodySigningAlgorithm
	RSASSA_PKCS1_V1_5_SHA_256 VerifyRequestBodySigningAlgorithm
	RSASSA_PKCS1_V1_5_SHA_384 VerifyRequestBodySigningAlgorithm
	RSASSA_PKCS1_V1_5_SHA_512 VerifyRequestBodySigningAlgorithm
	ECDSA_SHA_256             VerifyRequestBodySigningAlgorithm
	ECDSA_SHA_384             VerifyRequestBodySigningAlgorithm
	ECDSA_SHA_512             VerifyRequestBodySigningAlgorithm
	SM2_DSA_SM3               VerifyRequestBodySigningAlgorithm
}

func GetVerifyRequestBodySigningAlgorithmEnum() VerifyRequestBodySigningAlgorithmEnum {
	return VerifyRequestBodySigningAlgorithmEnum{
		RSASSA_PSS_SHA_256: VerifyRequestBodySigningAlgorithm{
			value: "RSASSA_PSS_SHA_256",
		},
		RSASSA_PSS_SHA_384: VerifyRequestBodySigningAlgorithm{
			value: "RSASSA_PSS_SHA_384",
		},
		RSASSA_PSS_SHA_512: VerifyRequestBodySigningAlgorithm{
			value: "RSASSA_PSS_SHA_512",
		},
		RSASSA_PKCS1_V1_5_SHA_256: VerifyRequestBodySigningAlgorithm{
			value: "RSASSA_PKCS1_V1_5_SHA_256",
		},
		RSASSA_PKCS1_V1_5_SHA_384: VerifyRequestBodySigningAlgorithm{
			value: "RSASSA_PKCS1_V1_5_SHA_384",
		},
		RSASSA_PKCS1_V1_5_SHA_512: VerifyRequestBodySigningAlgorithm{
			value: "RSASSA_PKCS1_V1_5_SHA_512",
		},
		ECDSA_SHA_256: VerifyRequestBodySigningAlgorithm{
			value: "ECDSA_SHA_256",
		},
		ECDSA_SHA_384: VerifyRequestBodySigningAlgorithm{
			value: "ECDSA_SHA_384",
		},
		ECDSA_SHA_512: VerifyRequestBodySigningAlgorithm{
			value: "ECDSA_SHA_512",
		},
		SM2_DSA_SM3: VerifyRequestBodySigningAlgorithm{
			value: "SM2DSA_SM3",
		},
	}
}

func (c VerifyRequestBodySigningAlgorithm) Value() string {
	return c.value
}

func (c VerifyRequestBodySigningAlgorithm) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *VerifyRequestBodySigningAlgorithm) UnmarshalJSON(b []byte) error {
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

type VerifyRequestBodyMessageType struct {
	value string
}

type VerifyRequestBodyMessageTypeEnum struct {
	DIGEST VerifyRequestBodyMessageType
	RAW    VerifyRequestBodyMessageType
}

func GetVerifyRequestBodyMessageTypeEnum() VerifyRequestBodyMessageTypeEnum {
	return VerifyRequestBodyMessageTypeEnum{
		DIGEST: VerifyRequestBodyMessageType{
			value: "DIGEST",
		},
		RAW: VerifyRequestBodyMessageType{
			value: "RAW",
		},
	}
}

func (c VerifyRequestBodyMessageType) Value() string {
	return c.value
}

func (c VerifyRequestBodyMessageType) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *VerifyRequestBodyMessageType) UnmarshalJSON(b []byte) error {
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
