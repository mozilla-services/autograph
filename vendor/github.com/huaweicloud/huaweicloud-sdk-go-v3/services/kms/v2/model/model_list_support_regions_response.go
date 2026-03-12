package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ListSupportRegionsResponse Response Object
type ListSupportRegionsResponse struct {

	// 区域信息。
	Regions        *[]string `json:"regions,omitempty"`
	HttpStatusCode int       `json:"-"`
}

func (o ListSupportRegionsResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ListSupportRegionsResponse struct{}"
	}

	return strings.Join([]string{"ListSupportRegionsResponse", string(data)}, " ")
}
