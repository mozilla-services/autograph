package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// UpdatePrimaryRegionRequest Request Object
type UpdatePrimaryRegionRequest struct {

	// 待更新的密钥ID，36字节，满足正则匹配“^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$”。 例如：0d0466b0-e727-4d9c-b35d-f84bb474a37f。
	KeyId string `json:"key_id"`

	Body *UpdatePrimaryRegionRequestBody `json:"body,omitempty"`
}

func (o UpdatePrimaryRegionRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "UpdatePrimaryRegionRequest struct{}"
	}

	return strings.Join([]string{"UpdatePrimaryRegionRequest", string(data)}, " ")
}
