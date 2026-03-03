package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ReplicateKeyRequest Request Object
type ReplicateKeyRequest struct {

	// 待复制的密钥ID，36字节，满足正则匹配“^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$”。 例如：0d0466b0-e727-4d9c-b35d-f84bb474a37f。
	KeyId string `json:"key_id"`

	Body *ReplicateKeyRequestBody `json:"body,omitempty"`
}

func (o ReplicateKeyRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ReplicateKeyRequest struct{}"
	}

	return strings.Join([]string{"ReplicateKeyRequest", string(data)}, " ")
}
