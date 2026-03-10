package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/converter"

	"strings"
)

type CreateRsaDatakeyPairRequestBody struct {

	// 密钥ID，36字节，满足正则匹配“^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$”。 例如：0d0466b0-e727-4d9c-b35d-f84bb474a37f。
	KeyId string `json:"key_id"`

	// 需要包含算法、长度、曲线信息。可选值有RSA_2048 | RSA_3072 | RSA_4096
	KeySpec CreateRsaDatakeyPairRequestBodyKeySpec `json:"key_spec"`

	// 是否返回明文私钥，默认为true
	WithPlainText *bool `json:"with_plain_text,omitempty"`

	// 认证加密的额外信息，请不要填写敏感信息
	AdditionalAuthenticatedData *string `json:"additional_authenticated_data,omitempty"`

	// 请求消息序列号，36字节序列号。 例如：919c82d4-8046-4722-9094-35c3c6524cff
	Sequence *string `json:"sequence,omitempty"`
}

func (o CreateRsaDatakeyPairRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CreateRsaDatakeyPairRequestBody struct{}"
	}

	return strings.Join([]string{"CreateRsaDatakeyPairRequestBody", string(data)}, " ")
}

type CreateRsaDatakeyPairRequestBodyKeySpec struct {
	value string
}

type CreateRsaDatakeyPairRequestBodyKeySpecEnum struct {
	RSA_2048 CreateRsaDatakeyPairRequestBodyKeySpec
	RSA_3072 CreateRsaDatakeyPairRequestBodyKeySpec
	RSA_4096 CreateRsaDatakeyPairRequestBodyKeySpec
}

func GetCreateRsaDatakeyPairRequestBodyKeySpecEnum() CreateRsaDatakeyPairRequestBodyKeySpecEnum {
	return CreateRsaDatakeyPairRequestBodyKeySpecEnum{
		RSA_2048: CreateRsaDatakeyPairRequestBodyKeySpec{
			value: "RSA_2048",
		},
		RSA_3072: CreateRsaDatakeyPairRequestBodyKeySpec{
			value: "RSA_3072",
		},
		RSA_4096: CreateRsaDatakeyPairRequestBodyKeySpec{
			value: "RSA_4096",
		},
	}
}

func (c CreateRsaDatakeyPairRequestBodyKeySpec) Value() string {
	return c.value
}

func (c CreateRsaDatakeyPairRequestBodyKeySpec) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *CreateRsaDatakeyPairRequestBodyKeySpec) UnmarshalJSON(b []byte) error {
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
