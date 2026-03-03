package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/converter"

	"strings"
)

// CreateKeyStoreRequestBody 创建专属密钥库请求体
type CreateKeyStoreRequestBody struct {

	// 专属密钥库别名，取值范围为1到255个字符，满足正则匹配“^[a-zA-Z0-9:/_-]{1,255}$”，且不与已有的专属密钥库别名重名。
	KeystoreAlias string `json:"keystore_alias"`

	// DHSM集群Id，要求集群当前未创建专属密钥库。
	HsmClusterId *string `json:"hsm_cluster_id,omitempty"`

	// DHSM集群的CA证书
	HsmCaCert *string `json:"hsm_ca_cert,omitempty"`

	// 集群ID。当类型为DHSM时，cluster_id为hsm_cluster_id。当类型为CDMS时，为cdms_cluster_id
	ClusterId *string `json:"cluster_id,omitempty"`

	// 专属密钥库集群类型。DHSM表示专属加密服务集群，CDMS表示密码卡集群,DEFAULT表示KMS原有集群
	KeystoreType *CreateKeyStoreRequestBodyKeystoreType `json:"keystore_type,omitempty"`
}

func (o CreateKeyStoreRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CreateKeyStoreRequestBody struct{}"
	}

	return strings.Join([]string{"CreateKeyStoreRequestBody", string(data)}, " ")
}

type CreateKeyStoreRequestBodyKeystoreType struct {
	value string
}

type CreateKeyStoreRequestBodyKeystoreTypeEnum struct {
	DEFAULT CreateKeyStoreRequestBodyKeystoreType
	DHSM    CreateKeyStoreRequestBodyKeystoreType
	CDMS    CreateKeyStoreRequestBodyKeystoreType
}

func GetCreateKeyStoreRequestBodyKeystoreTypeEnum() CreateKeyStoreRequestBodyKeystoreTypeEnum {
	return CreateKeyStoreRequestBodyKeystoreTypeEnum{
		DEFAULT: CreateKeyStoreRequestBodyKeystoreType{
			value: "DEFAULT",
		},
		DHSM: CreateKeyStoreRequestBodyKeystoreType{
			value: "DHSM",
		},
		CDMS: CreateKeyStoreRequestBodyKeystoreType{
			value: "CDMS",
		},
	}
}

func (c CreateKeyStoreRequestBodyKeystoreType) Value() string {
	return c.value
}

func (c CreateKeyStoreRequestBodyKeystoreType) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *CreateKeyStoreRequestBodyKeystoreType) UnmarshalJSON(b []byte) error {
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
