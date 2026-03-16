package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/converter"

	"strings"
)

type CreateDatakeyRequestBody struct {

	// 密钥ID，36字节，满足正则匹配“^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$”。 例如：0d0466b0-e727-4d9c-b35d-f84bb474a37f。
	KeyId string `json:"key_id"`

	// 指定生成的密钥bit位长度。有效值：AES_256、AES_128、SM4、HMAC_256、HMAC_384、HMAC_512、HMAC_SM3。  - AES_256：表示256比特的对称密钥。  - AES_128：表示128比特的对称密钥。  - SM4：表示SM4密钥。  - HMAC_256：表示HMAC_256密钥。  - HMAC_384：表示HMAC_384密钥。  - HMAC_512：表示HMAC_512密钥。  - HMAC_SM3：表示HMAC_SM3密钥。     说明：  datakey_length和key_spec二选一。   - 若datakey_length和key_spec都为空，默认生成256bit的密钥。   - 若datakey_length和key_spec都指定了值，仅datakey_length生效。
	KeySpec *CreateDatakeyRequestBodyKeySpec `json:"key_spec,omitempty"`

	// 密钥bit位长度。取值为8的倍数，取值范围为8~8192。 说明：  datakey_length和key_spec二选一。   - 若datakey_length和key_spec都为空，默认生成256bit的密钥。   - 若datakey_length和key_spec都指定了值，仅datakey_length生效。
	DatakeyLength *string `json:"datakey_length,omitempty"`

	// 身份验证的非敏感额外数据。任意字符串，长度不超过128字节。
	AdditionalAuthenticatedData *string `json:"additional_authenticated_data,omitempty"`

	// 请求消息序列号，36字节序列号。 例如：919c82d4-8046-4722-9094-35c3c6524cff
	Sequence *string `json:"sequence,omitempty"`

	// pin码，用于数据密钥的认证，仅四级密评场景生效
	Pin *string `json:"pin,omitempty"`

	// pin码的类型，默认为“CipherText”： - PlainText：表示明文pin - CipherText：表示密文pin
	PinType *CreateDatakeyRequestBodyPinType `json:"pin_type,omitempty"`
}

func (o CreateDatakeyRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CreateDatakeyRequestBody struct{}"
	}

	return strings.Join([]string{"CreateDatakeyRequestBody", string(data)}, " ")
}

type CreateDatakeyRequestBodyKeySpec struct {
	value string
}

type CreateDatakeyRequestBodyKeySpecEnum struct {
	AES_256  CreateDatakeyRequestBodyKeySpec
	AES_128  CreateDatakeyRequestBodyKeySpec
	SM4      CreateDatakeyRequestBodyKeySpec
	HMAC_256 CreateDatakeyRequestBodyKeySpec
	HMAC_384 CreateDatakeyRequestBodyKeySpec
	HMAC_512 CreateDatakeyRequestBodyKeySpec
	HMAC_SM3 CreateDatakeyRequestBodyKeySpec
}

func GetCreateDatakeyRequestBodyKeySpecEnum() CreateDatakeyRequestBodyKeySpecEnum {
	return CreateDatakeyRequestBodyKeySpecEnum{
		AES_256: CreateDatakeyRequestBodyKeySpec{
			value: "AES_256",
		},
		AES_128: CreateDatakeyRequestBodyKeySpec{
			value: "AES_128",
		},
		SM4: CreateDatakeyRequestBodyKeySpec{
			value: "SM4",
		},
		HMAC_256: CreateDatakeyRequestBodyKeySpec{
			value: "HMAC_256",
		},
		HMAC_384: CreateDatakeyRequestBodyKeySpec{
			value: "HMAC_384",
		},
		HMAC_512: CreateDatakeyRequestBodyKeySpec{
			value: "HMAC_512",
		},
		HMAC_SM3: CreateDatakeyRequestBodyKeySpec{
			value: "HMAC_SM3",
		},
	}
}

func (c CreateDatakeyRequestBodyKeySpec) Value() string {
	return c.value
}

func (c CreateDatakeyRequestBodyKeySpec) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *CreateDatakeyRequestBodyKeySpec) UnmarshalJSON(b []byte) error {
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

type CreateDatakeyRequestBodyPinType struct {
	value string
}

type CreateDatakeyRequestBodyPinTypeEnum struct {
	CIPHER_TEXT CreateDatakeyRequestBodyPinType
	PLAIN_TEXT  CreateDatakeyRequestBodyPinType
}

func GetCreateDatakeyRequestBodyPinTypeEnum() CreateDatakeyRequestBodyPinTypeEnum {
	return CreateDatakeyRequestBodyPinTypeEnum{
		CIPHER_TEXT: CreateDatakeyRequestBodyPinType{
			value: "CipherText",
		},
		PLAIN_TEXT: CreateDatakeyRequestBodyPinType{
			value: "PlainText",
		},
	}
}

func (c CreateDatakeyRequestBodyPinType) Value() string {
	return c.value
}

func (c CreateDatakeyRequestBodyPinType) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *CreateDatakeyRequestBodyPinType) UnmarshalJSON(b []byte) error {
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
