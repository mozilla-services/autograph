package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/converter"

	"strings"
)

// CreateEcDatakeyPairResponse Response Object
type CreateEcDatakeyPairResponse struct {

	// 密钥ID。
	KeyId *string `json:"key_id,omitempty"`

	// 需要包含算法、长度、曲线信息。可选值有RSA_2048 | RSA_3072 | RSA_4096 | ECC_NIST_P256 | ECC_NIST_P384 | ECC_NIST_P521 | ECC_SECG_P256K1 | SM2
	KeySpec *CreateEcDatakeyPairResponseKeySpec `json:"key_spec,omitempty"`

	// 明文公钥信息
	PublicKey *string `json:"public_key,omitempty"`

	// 密文私钥
	PrivateKeyCipherText *string `json:"private_key_cipher_text,omitempty"`

	// 明文私钥。private_key_plain_text、wrapped_private_key和ciphertext_recipient只能有一个有值
	PrivateKeyPlainText *string `json:"private_key_plain_text,omitempty"`

	// 由自定义私钥加密的密文私钥。private_key_plain_text、wrapped_private_key和ciphertext_recipient只能有一个有值
	WrappedPrivateKey *string `json:"wrapped_private_key,omitempty"`

	// 由擎天公钥信息加密的密文私钥。private_key_plain_text、wrapped_private_key和ciphertext_recipient只能有一个有值
	CiphertextRecipient *string `json:"ciphertext_recipient,omitempty"`
	HttpStatusCode      int     `json:"-"`
}

func (o CreateEcDatakeyPairResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CreateEcDatakeyPairResponse struct{}"
	}

	return strings.Join([]string{"CreateEcDatakeyPairResponse", string(data)}, " ")
}

type CreateEcDatakeyPairResponseKeySpec struct {
	value string
}

type CreateEcDatakeyPairResponseKeySpecEnum struct {
	RSA_2048         CreateEcDatakeyPairResponseKeySpec
	RSA_3072         CreateEcDatakeyPairResponseKeySpec
	RSA_4096         CreateEcDatakeyPairResponseKeySpec
	ECC_NIST_P256    CreateEcDatakeyPairResponseKeySpec
	ECC_NIST_P384    CreateEcDatakeyPairResponseKeySpec
	ECC_NIST_P521    CreateEcDatakeyPairResponseKeySpec
	ECC_SECG_P256_K1 CreateEcDatakeyPairResponseKeySpec
	SM2              CreateEcDatakeyPairResponseKeySpec
}

func GetCreateEcDatakeyPairResponseKeySpecEnum() CreateEcDatakeyPairResponseKeySpecEnum {
	return CreateEcDatakeyPairResponseKeySpecEnum{
		RSA_2048: CreateEcDatakeyPairResponseKeySpec{
			value: "RSA_2048",
		},
		RSA_3072: CreateEcDatakeyPairResponseKeySpec{
			value: "RSA_3072",
		},
		RSA_4096: CreateEcDatakeyPairResponseKeySpec{
			value: "RSA_4096",
		},
		ECC_NIST_P256: CreateEcDatakeyPairResponseKeySpec{
			value: "ECC_NIST_P256",
		},
		ECC_NIST_P384: CreateEcDatakeyPairResponseKeySpec{
			value: "ECC_NIST_P384",
		},
		ECC_NIST_P521: CreateEcDatakeyPairResponseKeySpec{
			value: "ECC_NIST_P521",
		},
		ECC_SECG_P256_K1: CreateEcDatakeyPairResponseKeySpec{
			value: "ECC_SECG_P256K1",
		},
		SM2: CreateEcDatakeyPairResponseKeySpec{
			value: "SM2",
		},
	}
}

func (c CreateEcDatakeyPairResponseKeySpec) Value() string {
	return c.value
}

func (c CreateEcDatakeyPairResponseKeySpec) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *CreateEcDatakeyPairResponseKeySpec) UnmarshalJSON(b []byte) error {
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
