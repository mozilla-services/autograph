package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

type ApiLink struct {

	// API的URL地址。
	Href *string `json:"href,omitempty"`

	// 默认值self。
	Rel *string `json:"rel,omitempty"`
}

func (o ApiLink) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ApiLink struct{}"
	}

	return strings.Join([]string{"ApiLink", string(data)}, " ")
}
