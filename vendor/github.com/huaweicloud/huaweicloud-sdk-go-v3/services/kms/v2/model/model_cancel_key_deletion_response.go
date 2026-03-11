package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// CancelKeyDeletionResponse Response Object
type CancelKeyDeletionResponse struct {

	// 密钥ID
	KeyId *string `json:"key_id,omitempty"`

	// 密钥状态： - 2为启用状态 - 3为禁用状态 - 4为计划删除状态 - 5为等待导入状态 - 7为冻结状态
	KeyState       *string `json:"key_state,omitempty"`
	HttpStatusCode int     `json:"-"`
}

func (o CancelKeyDeletionResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CancelKeyDeletionResponse struct{}"
	}

	return strings.Join([]string{"CancelKeyDeletionResponse", string(data)}, " ")
}
