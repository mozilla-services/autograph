package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ListSupportRegionsRequest Request Object
type ListSupportRegionsRequest struct {

	// 指定查询返回记录条数，默认值10。
	Limit *int32 `json:"limit,omitempty"`

	// 索引位置，从offset指定的下一条数据开始查询。
	Offset *int32 `json:"offset,omitempty"`
}

func (o ListSupportRegionsRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ListSupportRegionsRequest struct{}"
	}

	return strings.Join([]string{"ListSupportRegionsRequest", string(data)}, " ")
}
