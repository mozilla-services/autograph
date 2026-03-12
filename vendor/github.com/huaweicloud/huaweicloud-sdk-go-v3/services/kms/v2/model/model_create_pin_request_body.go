package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/converter"

	"strings"
)

type CreatePinRequestBody struct {

	// pin码的类型，默认为“CipherText”： - PlainText - CipherText
	PinType *CreatePinRequestBodyPinType `json:"pin_type,omitempty"`

	// 密钥库ID，指定密文pin时必选： 1：管理面manage_az集群（共享卡集群） 2：数据面共享集群(pod区) 其它：租户专属
	KeystoreId *string `json:"keystore_id,omitempty"`
}

func (o CreatePinRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CreatePinRequestBody struct{}"
	}

	return strings.Join([]string{"CreatePinRequestBody", string(data)}, " ")
}

type CreatePinRequestBodyPinType struct {
	value string
}

type CreatePinRequestBodyPinTypeEnum struct {
	CIPHER_TEXT CreatePinRequestBodyPinType
	PLAIN_TEXT  CreatePinRequestBodyPinType
}

func GetCreatePinRequestBodyPinTypeEnum() CreatePinRequestBodyPinTypeEnum {
	return CreatePinRequestBodyPinTypeEnum{
		CIPHER_TEXT: CreatePinRequestBodyPinType{
			value: "CipherText",
		},
		PLAIN_TEXT: CreatePinRequestBodyPinType{
			value: "PlainText",
		},
	}
}

func (c CreatePinRequestBodyPinType) Value() string {
	return c.value
}

func (c CreatePinRequestBodyPinType) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *CreatePinRequestBodyPinType) UnmarshalJSON(b []byte) error {
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
