package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ListKeysRequest Request Object
type ListKeysRequest struct {
	Body *ListKeysRequestBody `json:"body,omitempty"`
}

func (o ListKeysRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ListKeysRequest struct{}"
	}

	return strings.Join([]string{"ListKeysRequest", string(data)}, " ")
}
