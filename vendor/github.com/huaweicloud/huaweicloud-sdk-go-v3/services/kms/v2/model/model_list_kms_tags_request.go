package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ListKmsTagsRequest Request Object
type ListKmsTagsRequest struct {
}

func (o ListKmsTagsRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ListKmsTagsRequest struct{}"
	}

	return strings.Join([]string{"ListKmsTagsRequest", string(data)}, " ")
}
