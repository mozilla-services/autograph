package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ShowVersionsRequest Request Object
type ShowVersionsRequest struct {
}

func (o ShowVersionsRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ShowVersionsRequest struct{}"
	}

	return strings.Join([]string{"ShowVersionsRequest", string(data)}, " ")
}
