package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/converter"

	"strings"
)

type VerifyMacRequestBody struct {

	// 密钥ID
	KeyId string `json:"key_id"`

	// Mac算法，HMAC_SM3只有中国区支持。枚举如下： - HMAC_SHA_256 - HMAC_SHA_384 - HMAC_SHA_512 - HMAC_SM3
	MacAlgorithm VerifyMacRequestBodyMacAlgorithm `json:"mac_algorithm"`

	// 待处理消息。原消息最小长度1、最大长度4096。请将原消息转为Base64格式后传入
	Message string `json:"message"`

	// 待校验的消息验证码
	Mac string `json:"mac"`
}

func (o VerifyMacRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "VerifyMacRequestBody struct{}"
	}

	return strings.Join([]string{"VerifyMacRequestBody", string(data)}, " ")
}

type VerifyMacRequestBodyMacAlgorithm struct {
	value string
}

type VerifyMacRequestBodyMacAlgorithmEnum struct {
	HMAC_SHA_256 VerifyMacRequestBodyMacAlgorithm
	HMAC_SHA_384 VerifyMacRequestBodyMacAlgorithm
	HMAC_SHA_512 VerifyMacRequestBodyMacAlgorithm
	HMAC_SM3     VerifyMacRequestBodyMacAlgorithm
}

func GetVerifyMacRequestBodyMacAlgorithmEnum() VerifyMacRequestBodyMacAlgorithmEnum {
	return VerifyMacRequestBodyMacAlgorithmEnum{
		HMAC_SHA_256: VerifyMacRequestBodyMacAlgorithm{
			value: "HMAC_SHA_256",
		},
		HMAC_SHA_384: VerifyMacRequestBodyMacAlgorithm{
			value: "HMAC_SHA_384",
		},
		HMAC_SHA_512: VerifyMacRequestBodyMacAlgorithm{
			value: "HMAC_SHA_512",
		},
		HMAC_SM3: VerifyMacRequestBodyMacAlgorithm{
			value: "HMAC_SM3",
		},
	}
}

func (c VerifyMacRequestBodyMacAlgorithm) Value() string {
	return c.value
}

func (c VerifyMacRequestBodyMacAlgorithm) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *VerifyMacRequestBodyMacAlgorithm) UnmarshalJSON(b []byte) error {
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
