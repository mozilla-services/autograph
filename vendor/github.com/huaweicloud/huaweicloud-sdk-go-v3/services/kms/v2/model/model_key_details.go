package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/converter"

	"strings"
)

// KeyDetails 密钥详情。
type KeyDetails struct {

	// 密钥ID。
	KeyId *string `json:"key_id,omitempty"`

	// 用户域ID。
	DomainId *string `json:"domain_id,omitempty"`

	// 密钥别名。
	KeyAlias *string `json:"key_alias,omitempty"`

	// 密钥区域。
	Realm *string `json:"realm,omitempty"`

	// 密钥生成算法。  - AES_256  - SM4  - RSA_2048  - RSA_3072  - RSA_4096  - EC_P256  - EC_P384  - SM2
	KeySpec *KeyDetailsKeySpec `json:"key_spec,omitempty"`

	// 密钥用途。 - ENCRYPT_DECRYPT - SIGN_VERIFY
	KeyUsage *KeyDetailsKeyUsage `json:"key_usage,omitempty"`

	// 密钥描述。
	KeyDescription *string `json:"key_description,omitempty"`

	// 密钥创建时间，时间戳，即从1970年1月1日至该时间的总秒数。
	CreationDate *string `json:"creation_date,omitempty"`

	// 密钥计划删除时间，时间戳，即从1970年1月1日至该时间的总秒数。
	ScheduledDeletionDate *string `json:"scheduled_deletion_date,omitempty"`

	// 密钥状态，满足正则匹配“^[1-5]{1}$”，枚举如下：  - “1”表示待激活状态  - “2”表示启用状态  - “3”表示禁用状态  - “4”表示计划删除状态  - “5”表示等待导入状态
	KeyState *string `json:"key_state,omitempty"`

	// 默认主密钥标识，默认主密钥标识为1，非默认标识为0。
	DefaultKeyFlag *string `json:"default_key_flag,omitempty"`

	// 密钥类型。
	KeyType *string `json:"key_type,omitempty"`

	// 密钥材料失效时间，时间戳，即从1970年1月1日至该时间的总秒数。
	ExpirationTime *string `json:"expiration_time,omitempty"`

	// 密钥来源，默认为“kms”，枚举如下：  - kms表示密钥材料由kms生成kms表示密钥材料由kms生成  - external表示密钥材料由外部导入
	Origin *KeyDetailsOrigin `json:"origin,omitempty"`

	// 密钥轮换状态，默认为“false”，表示关闭密钥轮换功能。
	KeyRotationEnabled *string `json:"key_rotation_enabled,omitempty"`

	// 企业项目ID，默认为“0”。  - 对于开通企业项目的用户，表示资源处于默认企业项目下。  - 对于未开通企业项目的用户，表示资源未处于企业项目下。
	SysEnterpriseProjectId *string `json:"sys_enterprise_project_id,omitempty"`

	// 密钥库ID
	KeystoreId *string `json:"keystore_id,omitempty"`
}

func (o KeyDetails) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "KeyDetails struct{}"
	}

	return strings.Join([]string{"KeyDetails", string(data)}, " ")
}

type KeyDetailsKeySpec struct {
	value string
}

type KeyDetailsKeySpecEnum struct {
	AES_256  KeyDetailsKeySpec
	SM4      KeyDetailsKeySpec
	RSA_2048 KeyDetailsKeySpec
	RSA_3072 KeyDetailsKeySpec
	RSA_4096 KeyDetailsKeySpec
	EC_P256  KeyDetailsKeySpec
	EC_P384  KeyDetailsKeySpec
	SM2      KeyDetailsKeySpec
}

func GetKeyDetailsKeySpecEnum() KeyDetailsKeySpecEnum {
	return KeyDetailsKeySpecEnum{
		AES_256: KeyDetailsKeySpec{
			value: "AES_256",
		},
		SM4: KeyDetailsKeySpec{
			value: "SM4",
		},
		RSA_2048: KeyDetailsKeySpec{
			value: "RSA_2048",
		},
		RSA_3072: KeyDetailsKeySpec{
			value: "RSA_3072",
		},
		RSA_4096: KeyDetailsKeySpec{
			value: "RSA_4096",
		},
		EC_P256: KeyDetailsKeySpec{
			value: "EC_P256",
		},
		EC_P384: KeyDetailsKeySpec{
			value: "EC_P384",
		},
		SM2: KeyDetailsKeySpec{
			value: "SM2",
		},
	}
}

func (c KeyDetailsKeySpec) Value() string {
	return c.value
}

func (c KeyDetailsKeySpec) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *KeyDetailsKeySpec) UnmarshalJSON(b []byte) error {
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

type KeyDetailsKeyUsage struct {
	value string
}

type KeyDetailsKeyUsageEnum struct {
	ENCRYPT_DECRYPT KeyDetailsKeyUsage
	SIGN_VERIFY     KeyDetailsKeyUsage
}

func GetKeyDetailsKeyUsageEnum() KeyDetailsKeyUsageEnum {
	return KeyDetailsKeyUsageEnum{
		ENCRYPT_DECRYPT: KeyDetailsKeyUsage{
			value: "ENCRYPT_DECRYPT",
		},
		SIGN_VERIFY: KeyDetailsKeyUsage{
			value: "SIGN_VERIFY",
		},
	}
}

func (c KeyDetailsKeyUsage) Value() string {
	return c.value
}

func (c KeyDetailsKeyUsage) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *KeyDetailsKeyUsage) UnmarshalJSON(b []byte) error {
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

type KeyDetailsOrigin struct {
	value string
}

type KeyDetailsOriginEnum struct {
	KMS      KeyDetailsOrigin
	EXTERNAL KeyDetailsOrigin
}

func GetKeyDetailsOriginEnum() KeyDetailsOriginEnum {
	return KeyDetailsOriginEnum{
		KMS: KeyDetailsOrigin{
			value: "kms",
		},
		EXTERNAL: KeyDetailsOrigin{
			value: "external",
		},
	}
}

func (c KeyDetailsOrigin) Value() string {
	return c.value
}

func (c KeyDetailsOrigin) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *KeyDetailsOrigin) UnmarshalJSON(b []byte) error {
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
