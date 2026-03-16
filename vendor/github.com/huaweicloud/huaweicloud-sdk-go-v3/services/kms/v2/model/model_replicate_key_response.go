package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ReplicateKeyResponse Response Object
type ReplicateKeyResponse struct {

	// 复制出的密钥ID，36字节，满足正则匹配“^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$”。 例如：0d0466b0-e727-4d9c-b35d-f84bb474a37f。
	KeyId *string `json:"key_id,omitempty"`

	// 用户域ID。
	DomainId *string `json:"domain_id,omitempty"`

	// 复制出的密钥所在区域编码。如cn-north-4。
	Region         *string `json:"region,omitempty"`
	HttpStatusCode int     `json:"-"`
}

func (o ReplicateKeyResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ReplicateKeyResponse struct{}"
	}

	return strings.Join([]string{"ReplicateKeyResponse", string(data)}, " ")
}
