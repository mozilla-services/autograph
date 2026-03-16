package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ShowVersionResponse Response Object
type ShowVersionResponse struct {

	// 描述version 对象的列表，详情请参见 ApiVersionDetail字段数据结构说明。
	Version        *interface{} `json:"version,omitempty"`
	HttpStatusCode int          `json:"-"`
}

func (o ShowVersionResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ShowVersionResponse struct{}"
	}

	return strings.Join([]string{"ShowVersionResponse", string(data)}, " ")
}
