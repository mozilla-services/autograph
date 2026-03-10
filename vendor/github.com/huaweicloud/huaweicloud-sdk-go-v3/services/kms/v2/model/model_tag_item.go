package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// TagItem 标签。
type TagItem struct {

	// 键。 最大长度36个unicode字符。 key不能为空。不能包含非打印字符“ASCII(0-31)”、“*”、“<”、“>”、“\\”、“=”。
	Key string `json:"key"`

	// 值。 每个值最大长度43个unicode字符，可以为空字符串。 不能包含非打印字符“ASCII(0-31)”、“*”、“<”、“>”、“\\”、“=”。
	Value *string `json:"value,omitempty"`
}

func (o TagItem) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "TagItem struct{}"
	}

	return strings.Join([]string{"TagItem", string(data)}, " ")
}
