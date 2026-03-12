package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ListGrantsRequest Request Object
type ListGrantsRequest struct {
	Body *ListGrantsRequestBody `json:"body,omitempty"`
}

func (o ListGrantsRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ListGrantsRequest struct{}"
	}

	return strings.Join([]string{"ListGrantsRequest", string(data)}, " ")
}
