package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/converter"

	"strings"
)

type CreateGrantRequestBody struct {

	// 密钥ID，36字节，满足正则匹配“^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$”。 例如：0d0466b0-e727-4d9c-b35d-f84bb474a37f。
	KeyId string `json:"key_id"`

	// 被授权用户ID，1~64字节，满足正则匹配“^[a-zA-Z0-9]{1，64}$”。 例如：0d0466b00d0466b00d0466b00d0466b0
	GranteePrincipal string `json:"grantee_principal"`

	// 授权允许的操作列表。 有效的值：“create-datakey”，“create-datakey-without-plaintext”，“encrypt-datakey”，“decrypt-datakey”，“describe-key”，“create-grant”，“retire-grant”，“encrypt-data”，“decrypt-data”。 有效值不能仅为“create-grant”。  - “create-datakey” 创建数据密钥  - “create-datakey-without-plaintext” 创建不含明文数据密钥  - “encrypt-datakey” 加密数据密钥  - “decrypt-datakey” 解密数据密钥  - “describe-key” 查询密钥信息  - “retire-grant” 退役授权  - “encrypt-data” 加密数据  - “decrypt-data” 解密数据
	Operations []string `json:"operations"`

	// 授权名称，取值1到255字符，满足正则匹配“^[a-zA-Z0-9:/_-]{1,255}$”。
	Name *string `json:"name,omitempty"`

	// 可退役授权的用户ID，1~64字节，满足正则匹配“^[a-zA-Z0-9]{1，64}$”。 例如：0d0466b00d0466b00d0466b00d0466b0
	RetiringPrincipal *string `json:"retiring_principal,omitempty"`

	// 授权类型。有效值：“user”，“domain”。默认值为“user”。
	GranteePrincipalType *CreateGrantRequestBodyGranteePrincipalType `json:"grantee_principal_type,omitempty"`

	// 请求消息序列号，36字节序列号。 例如：919c82d4-8046-4722-9094-35c3c6524cff
	Sequence *string `json:"sequence,omitempty"`
}

func (o CreateGrantRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CreateGrantRequestBody struct{}"
	}

	return strings.Join([]string{"CreateGrantRequestBody", string(data)}, " ")
}

type CreateGrantRequestBodyGranteePrincipalType struct {
	value string
}

type CreateGrantRequestBodyGranteePrincipalTypeEnum struct {
	USER   CreateGrantRequestBodyGranteePrincipalType
	DOMAIN CreateGrantRequestBodyGranteePrincipalType
}

func GetCreateGrantRequestBodyGranteePrincipalTypeEnum() CreateGrantRequestBodyGranteePrincipalTypeEnum {
	return CreateGrantRequestBodyGranteePrincipalTypeEnum{
		USER: CreateGrantRequestBodyGranteePrincipalType{
			value: "user",
		},
		DOMAIN: CreateGrantRequestBodyGranteePrincipalType{
			value: "domain",
		},
	}
}

func (c CreateGrantRequestBodyGranteePrincipalType) Value() string {
	return c.value
}

func (c CreateGrantRequestBodyGranteePrincipalType) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *CreateGrantRequestBodyGranteePrincipalType) UnmarshalJSON(b []byte) error {
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
