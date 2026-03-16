package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// CreateKmsTagRequestBody 创建KMS资源标签请求体。
type CreateKmsTagRequestBody struct {
	Tag *TagItem `json:"tag,omitempty"`

	// 请求消息序列号，36字节序列号。 例如：919c82d4-8046-4722-9094-35c3c6524cff
	Sequence *string `json:"sequence,omitempty"`
}

func (o CreateKmsTagRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CreateKmsTagRequestBody struct{}"
	}

	return strings.Join([]string{"CreateKmsTagRequestBody", string(data)}, " ")
}
