package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/converter"

	"strings"
)

type DeriveSharedSecretRequestBody struct {

	// 密钥ID
	KeyId string `json:"key_id"`

	// 密钥协商算法，仅支持ECDH
	KeyAgreementAlgorithm DeriveSharedSecretRequestBodyKeyAgreementAlgorithm `json:"key_agreement_algorithm"`

	// 对端密钥对的的公钥，您需要保证是EC_P256，EC_384，SECP256K1或SM2(仅中国区域支持)密钥对的公钥。公钥的格式必须是DER-encoded X.509类型的Base64的字符串
	PublicKey string `json:"public_key"`

	Recipient *Recipient `json:"recipient,omitempty"`
}

func (o DeriveSharedSecretRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "DeriveSharedSecretRequestBody struct{}"
	}

	return strings.Join([]string{"DeriveSharedSecretRequestBody", string(data)}, " ")
}

type DeriveSharedSecretRequestBodyKeyAgreementAlgorithm struct {
	value string
}

type DeriveSharedSecretRequestBodyKeyAgreementAlgorithmEnum struct {
	ECDH DeriveSharedSecretRequestBodyKeyAgreementAlgorithm
}

func GetDeriveSharedSecretRequestBodyKeyAgreementAlgorithmEnum() DeriveSharedSecretRequestBodyKeyAgreementAlgorithmEnum {
	return DeriveSharedSecretRequestBodyKeyAgreementAlgorithmEnum{
		ECDH: DeriveSharedSecretRequestBodyKeyAgreementAlgorithm{
			value: "ECDH",
		},
	}
}

func (c DeriveSharedSecretRequestBodyKeyAgreementAlgorithm) Value() string {
	return c.value
}

func (c DeriveSharedSecretRequestBodyKeyAgreementAlgorithm) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *DeriveSharedSecretRequestBodyKeyAgreementAlgorithm) UnmarshalJSON(b []byte) error {
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
