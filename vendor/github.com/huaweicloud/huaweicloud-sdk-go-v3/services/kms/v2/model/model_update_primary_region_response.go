package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// UpdatePrimaryRegionResponse Response Object
type UpdatePrimaryRegionResponse struct {

	// 密钥ID，36字节，满足正则匹配“^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$”。 例如：0d0466b0-e727-4d9c-b35d-f84bb474a37f。
	KeyId *string `json:"key_id,omitempty"`

	// 密钥所在主区域编码。如cn-north-4。
	PrimaryRegion  *string `json:"primary_region,omitempty"`
	HttpStatusCode int     `json:"-"`
}

func (o UpdatePrimaryRegionResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "UpdatePrimaryRegionResponse struct{}"
	}

	return strings.Join([]string{"UpdatePrimaryRegionResponse", string(data)}, " ")
}
