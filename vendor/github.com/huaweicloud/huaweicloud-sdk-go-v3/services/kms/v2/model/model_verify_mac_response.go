package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// VerifyMacResponse Response Object
type VerifyMacResponse struct {

	// 密钥ID
	KeyId *string `json:"key_id,omitempty"`

	// MAC算法
	MacAlgorithm *string `json:"mac_algorithm,omitempty"`

	// 消息验证码校验结果
	MacValid       *bool `json:"mac_valid,omitempty"`
	HttpStatusCode int   `json:"-"`
}

func (o VerifyMacResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "VerifyMacResponse struct{}"
	}

	return strings.Join([]string{"VerifyMacResponse", string(data)}, " ")
}
