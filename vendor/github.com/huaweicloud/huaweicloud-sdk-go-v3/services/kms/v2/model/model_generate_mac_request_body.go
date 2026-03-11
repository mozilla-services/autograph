package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/converter"

	"strings"
)

type GenerateMacRequestBody struct {

	// 密钥ID
	KeyId string `json:"key_id"`

	// Mac算法，HMAC_SM3只有中国区支持。枚举如下： - HMAC_SHA_256 - HMAC_SHA_384 - HMAC_SHA_512 - HMAC_SM3
	MacAlgorithm GenerateMacRequestBodyMacAlgorithm `json:"mac_algorithm"`

	// 待处理消息。原消息最小长度1、最大长度4096。请将原消息转为Base64格式后传入
	Message string `json:"message"`
}

func (o GenerateMacRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "GenerateMacRequestBody struct{}"
	}

	return strings.Join([]string{"GenerateMacRequestBody", string(data)}, " ")
}

type GenerateMacRequestBodyMacAlgorithm struct {
	value string
}

type GenerateMacRequestBodyMacAlgorithmEnum struct {
	HMAC_SHA_256 GenerateMacRequestBodyMacAlgorithm
	HMAC_SHA_384 GenerateMacRequestBodyMacAlgorithm
	HMAC_SHA_512 GenerateMacRequestBodyMacAlgorithm
	HMAC_SM3     GenerateMacRequestBodyMacAlgorithm
}

func GetGenerateMacRequestBodyMacAlgorithmEnum() GenerateMacRequestBodyMacAlgorithmEnum {
	return GenerateMacRequestBodyMacAlgorithmEnum{
		HMAC_SHA_256: GenerateMacRequestBodyMacAlgorithm{
			value: "HMAC_SHA_256",
		},
		HMAC_SHA_384: GenerateMacRequestBodyMacAlgorithm{
			value: "HMAC_SHA_384",
		},
		HMAC_SHA_512: GenerateMacRequestBodyMacAlgorithm{
			value: "HMAC_SHA_512",
		},
		HMAC_SM3: GenerateMacRequestBodyMacAlgorithm{
			value: "HMAC_SM3",
		},
	}
}

func (c GenerateMacRequestBodyMacAlgorithm) Value() string {
	return c.value
}

func (c GenerateMacRequestBodyMacAlgorithm) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *GenerateMacRequestBodyMacAlgorithm) UnmarshalJSON(b []byte) error {
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
