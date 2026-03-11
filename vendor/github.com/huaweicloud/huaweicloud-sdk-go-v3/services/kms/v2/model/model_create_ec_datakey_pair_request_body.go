package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/converter"

	"strings"
)

type CreateEcDatakeyPairRequestBody struct {

	// 密钥ID，36字节，满足正则匹配“^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$”。 例如：0d0466b0-e727-4d9c-b35d-f84bb474a37f。
	KeyId string `json:"key_id"`

	// 需要包含算法、长度、曲线信息。可选值有ECC_NIST_P256 | ECC_NIST_P384 | ECC_NIST_P521 | ECC_SECG_P256K1 | SM2
	KeySpec CreateEcDatakeyPairRequestBodyKeySpec `json:"key_spec"`

	// 是否返回明文私钥，默认为true
	WithPlainText *bool `json:"with_plain_text,omitempty"`

	// 认证加密的额外信息，请不要填写敏感信息
	AdditionalAuthenticatedData *string `json:"additional_authenticated_data,omitempty"`

	// 请求消息序列号，36字节序列号。 例如：919c82d4-8046-4722-9094-35c3c6524cff
	Sequence *string `json:"sequence,omitempty"`

	// 指定PIN码保护。仅四级密评场景支持该参数。
	Pin *string `json:"pin,omitempty"`

	// pin码的类型，默认为“CipherText”，可选“PlainText”。仅四级密评场景支持该参数。
	PinType *string `json:"pin_type,omitempty"`
}

func (o CreateEcDatakeyPairRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CreateEcDatakeyPairRequestBody struct{}"
	}

	return strings.Join([]string{"CreateEcDatakeyPairRequestBody", string(data)}, " ")
}

type CreateEcDatakeyPairRequestBodyKeySpec struct {
	value string
}

type CreateEcDatakeyPairRequestBodyKeySpecEnum struct {
	ECC_NIST_P256    CreateEcDatakeyPairRequestBodyKeySpec
	ECC_NIST_P384    CreateEcDatakeyPairRequestBodyKeySpec
	ECC_NIST_P521    CreateEcDatakeyPairRequestBodyKeySpec
	ECC_SECG_P256_K1 CreateEcDatakeyPairRequestBodyKeySpec
	SM2              CreateEcDatakeyPairRequestBodyKeySpec
}

func GetCreateEcDatakeyPairRequestBodyKeySpecEnum() CreateEcDatakeyPairRequestBodyKeySpecEnum {
	return CreateEcDatakeyPairRequestBodyKeySpecEnum{
		ECC_NIST_P256: CreateEcDatakeyPairRequestBodyKeySpec{
			value: "ECC_NIST_P256",
		},
		ECC_NIST_P384: CreateEcDatakeyPairRequestBodyKeySpec{
			value: "ECC_NIST_P384",
		},
		ECC_NIST_P521: CreateEcDatakeyPairRequestBodyKeySpec{
			value: "ECC_NIST_P521",
		},
		ECC_SECG_P256_K1: CreateEcDatakeyPairRequestBodyKeySpec{
			value: "ECC_SECG_P256K1",
		},
		SM2: CreateEcDatakeyPairRequestBodyKeySpec{
			value: "SM2",
		},
	}
}

func (c CreateEcDatakeyPairRequestBodyKeySpec) Value() string {
	return c.value
}

func (c CreateEcDatakeyPairRequestBodyKeySpec) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *CreateEcDatakeyPairRequestBodyKeySpec) UnmarshalJSON(b []byte) error {
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
