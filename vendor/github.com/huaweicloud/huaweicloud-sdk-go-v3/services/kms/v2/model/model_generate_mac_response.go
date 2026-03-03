package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// GenerateMacResponse Response Object
type GenerateMacResponse struct {

	// 密钥ID
	KeyId *string `json:"key_id,omitempty"`

	// Mac算法
	MacAlgorithm *string `json:"mac_algorithm,omitempty"`

	// 生成的消息验证码
	Mac            *string `json:"mac,omitempty"`
	HttpStatusCode int     `json:"-"`
}

func (o GenerateMacResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "GenerateMacResponse struct{}"
	}

	return strings.Join([]string{"GenerateMacResponse", string(data)}, " ")
}
