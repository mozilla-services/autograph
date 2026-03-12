package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// KeKInfo 密钥详细信息。
type KeKInfo struct {

	// 密钥ID。
	KeyId *string `json:"key_id,omitempty"`

	// 用户域ID。
	DomainId *string `json:"domain_id,omitempty"`

	// region ID。
	RegionId *string `json:"region_id,omitempty"`
}

func (o KeKInfo) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "KeKInfo struct{}"
	}

	return strings.Join([]string{"KeKInfo", string(data)}, " ")
}
