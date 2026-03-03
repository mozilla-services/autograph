package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/converter"

	"strings"
)

type GetParametersForImportRequestBody struct {

	// 密钥ID，36字节，满足正则匹配“^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$”。 例如：0d0466b0-e727-4d9c-b35d-f84bb474a37f。
	KeyId string `json:"key_id"`

	// 密钥材料加密算法，枚举如下：  - RSAES_OAEP_SHA_256  - SM2_ENCRYPT，部分局点不支持该导入类型
	WrappingAlgorithm GetParametersForImportRequestBodyWrappingAlgorithm `json:"wrapping_algorithm"`

	// 请求消息序列号，36字节序列号。 例如：919c82d4-8046-4722-9094-35c3c6524cff
	Sequence *string `json:"sequence,omitempty"`
}

func (o GetParametersForImportRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "GetParametersForImportRequestBody struct{}"
	}

	return strings.Join([]string{"GetParametersForImportRequestBody", string(data)}, " ")
}

type GetParametersForImportRequestBodyWrappingAlgorithm struct {
	value string
}

type GetParametersForImportRequestBodyWrappingAlgorithmEnum struct {
	RSAES_OAEP_SHA_256 GetParametersForImportRequestBodyWrappingAlgorithm
	SM2_ENCRYPT        GetParametersForImportRequestBodyWrappingAlgorithm
}

func GetGetParametersForImportRequestBodyWrappingAlgorithmEnum() GetParametersForImportRequestBodyWrappingAlgorithmEnum {
	return GetParametersForImportRequestBodyWrappingAlgorithmEnum{
		RSAES_OAEP_SHA_256: GetParametersForImportRequestBodyWrappingAlgorithm{
			value: "RSAES_OAEP_SHA_256",
		},
		SM2_ENCRYPT: GetParametersForImportRequestBodyWrappingAlgorithm{
			value: "SM2_ENCRYPT",
		},
	}
}

func (c GetParametersForImportRequestBodyWrappingAlgorithm) Value() string {
	return c.value
}

func (c GetParametersForImportRequestBodyWrappingAlgorithm) MarshalJSON() ([]byte, error) {
	return utils.Marshal(c.value)
}

func (c *GetParametersForImportRequestBodyWrappingAlgorithm) UnmarshalJSON(b []byte) error {
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
