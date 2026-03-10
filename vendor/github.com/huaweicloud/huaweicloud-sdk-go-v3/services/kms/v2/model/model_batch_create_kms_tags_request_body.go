package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

type BatchCreateKmsTagsRequestBody struct {

	// 标签列表，key和value键值对的集合。
	Tags []TagItem `json:"tags"`

	// 操作标识： 仅限于“create”和“delete”。
	Action string `json:"action"`

	// 请求消息序列号，36字节序列号。 例如：919c82d4-8046-4722-9094-35c3c6524cff
	Sequence *string `json:"sequence,omitempty"`
}

func (o BatchCreateKmsTagsRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "BatchCreateKmsTagsRequestBody struct{}"
	}

	return strings.Join([]string{"BatchCreateKmsTagsRequestBody", string(data)}, " ")
}
