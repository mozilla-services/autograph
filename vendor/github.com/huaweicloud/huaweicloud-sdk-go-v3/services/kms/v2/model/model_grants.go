package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/converter"

	"strings"
)

type Grants struct {

	// 密钥ID。
	KeyId *string `json:"key_id,omitempty"`

	// 授权ID，64字节。
	GrantId *string `json:"grant_id,omitempty"`

	// 被授权用户ID，1~64字节，满足正则匹配“^[a-zA-Z0-9]{1，64}$”。 例如：0d0466b00d0466b00d0466b00d0466b0
	GranteePrincipal *string `json:"grantee_principal,omitempty"`

	// 授权类型。 有效值：“user”，“domain”。
	GranteePrincipalType *GrantsGranteePrincipalType `json:"grantee_principal_type,omitempty"`

	// 授权允许的操作列表。 有效的值：“create-datakey”，“create-datakey-without-plaintext”，“encrypt-datakey”，“decrypt-datakey”，“describe-key”，“create-grant”，“retire-grant”，“encrypt-data”，“decrypt-data”。 有效值不能仅为“create-grant”。  - “create-datakey” 创建数据密钥  - “create-datakey-without-plaintext” 创建不含明文数据密钥  - “encrypt-datakey” 加密数据密钥  - “decrypt-datakey” 解密数据密钥  - “describe-key” 查询密钥信息  - “retire-grant” 退役授权  - “encrypt-data” 加密数据  - “decrypt-data” 解密数据
	Operations *[]string `json:"operations,omitempty"`

	// 创建授权用户ID，1~64字节，满足正则匹配“^[a-zA-Z0-9]{1，64}$”。 例如：0d0466b00d0466b00d0466b00d0466b0
	IssuingPrincipal *string `json:"issuing_principal,omitempty"`

	// 创建时间，时间戳，即从1970年1月1日至该时间的总秒数。 例如：1497341531000
	CreationDate *string `json:"creation_date,omitempty"`

	// 授权名字，取值1到255字符，满足正则匹配“^[a-zA-Z0-9:/_-]{1,255}$”。
	Name *string `json:"name,omitempty"`

	// 可退役授权的用户ID，1~64字节，满足正则匹配“^[a-zA-Z0-9]{1，64}$”。 例如：0d0466b00d0466b00d0466b00d0466b0
	RetiringPrincipal *string `json:"retiring_principal,omitempty"`
}

func (o Grants) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "Grants struct{}"
	}

	return strings.Join([]string{"Grants", string(data)}, " ")
}

type GrantsGranteePrincipalType struct {
	value string
}

type GrantsGranteePrincipalTypeEnum struct {
	USER   GrantsGranteePrincipalType
	DOMAIN GrantsGranteePrincipalType
}

func GetGrantsGranteePrincipalTypeEnum() GrantsGranteePrincipalTypeEnum {
	return GrantsGranteePrincipalTypeEnum{
		USER: GrantsGranteePrincipalType{
			value: "user",
		},
		DOMAIN: GrantsGranteePrincipalType{
			value: "domain",
		},
	}
}

func (c GrantsGranteePrincipalType) Value() string {
	return c.value
}

func (c GrantsGranteePrincipalType) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *GrantsGranteePrincipalType) UnmarshalJSON(b []byte) error {
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
