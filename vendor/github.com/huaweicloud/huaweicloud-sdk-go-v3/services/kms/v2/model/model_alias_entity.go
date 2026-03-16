package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// AliasEntity 别名消息体
type AliasEntity struct {

	// 账号ID
	DomainId *string `json:"domain_id,omitempty"`

	// 密钥ID
	KeyId *string `json:"key_id,omitempty"`

	// 别名
	Alias string `json:"alias"`

	// 别名资源定位符
	AliasUrn string `json:"alias_urn"`

	// 创建时间
	CreateTime *string `json:"create_time,omitempty"`

	// 更新时间
	UpdateTime *string `json:"update_time,omitempty"`
}

func (o AliasEntity) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "AliasEntity struct{}"
	}

	return strings.Join([]string{"AliasEntity", string(data)}, " ")
}
