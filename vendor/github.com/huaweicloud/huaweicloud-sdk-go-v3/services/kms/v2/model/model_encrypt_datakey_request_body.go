package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/converter"

	"strings"
)

type EncryptDatakeyRequestBody struct {

	// 密钥ID，36字节，满足正则匹配“^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$”。 例如：0d0466b0-e727-4d9c-b35d-f84bb474a37f。
	KeyId string `json:"key_id"`

	// CMK为AES时，DEK明文和DEK明文的SHA256（32字节）；CMK为SM4时，DEK明文和DEK明文的SM3（32字节），均为16进制字符串表示。
	PlainText string `json:"plain_text"`

	// DEK明文字节长度，取值范围为1~1024。 DEK明文字节长度，取值为“64”。
	DatakeyPlainLength string `json:"datakey_plain_length"`

	// 身份验证的非敏感额外数据。任意字符串，长度不超过128字节。
	AdditionalAuthenticatedData *string `json:"additional_authenticated_data,omitempty"`

	// 请求消息序列号，36字节序列号。 例如：919c82d4-8046-4722-9094-35c3c6524cff
	Sequence *string `json:"sequence,omitempty"`

	// 指定PIN码保护。仅四级密评场景支持该参数。
	Pin *string `json:"pin,omitempty"`

	// pin码的类型，默认为“CipherText”，可选“PlainText”。仅四级密评场景支持该参数。
	PinType *string `json:"pin_type,omitempty"`

	// 指定待加密数据密钥的类型，仅四级密评场景生效。有效值： SM2、RSA。
	KeySpec *EncryptDatakeyRequestBodyKeySpec `json:"key_spec,omitempty"`
}

func (o EncryptDatakeyRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "EncryptDatakeyRequestBody struct{}"
	}

	return strings.Join([]string{"EncryptDatakeyRequestBody", string(data)}, " ")
}

type EncryptDatakeyRequestBodyKeySpec struct {
	value string
}

type EncryptDatakeyRequestBodyKeySpecEnum struct {
	SM2 EncryptDatakeyRequestBodyKeySpec
	RSA EncryptDatakeyRequestBodyKeySpec
}

func GetEncryptDatakeyRequestBodyKeySpecEnum() EncryptDatakeyRequestBodyKeySpecEnum {
	return EncryptDatakeyRequestBodyKeySpecEnum{
		SM2: EncryptDatakeyRequestBodyKeySpec{
			value: "SM2",
		},
		RSA: EncryptDatakeyRequestBodyKeySpec{
			value: "RSA",
		},
	}
}

func (c EncryptDatakeyRequestBodyKeySpec) Value() string {
	return c.value
}

func (c EncryptDatakeyRequestBodyKeySpec) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *EncryptDatakeyRequestBodyKeySpec) UnmarshalJSON(b []byte) error {
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
