package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// KeyStatusInfo 密钥状态信息。
type KeyStatusInfo struct {

	// 密钥ID
	KeyId *string `json:"key_id,omitempty"`

	// 密钥状态： - 2为启用状态 - 3为禁用状态 - 4为计划删除状态 - 5为等待导入状态 - 7为冻结状态
	KeyState *string `json:"key_state,omitempty"`
}

func (o KeyStatusInfo) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "KeyStatusInfo struct{}"
	}

	return strings.Join([]string{"KeyStatusInfo", string(data)}, " ")
}
