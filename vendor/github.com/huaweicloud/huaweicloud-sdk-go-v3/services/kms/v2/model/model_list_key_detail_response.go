package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ListKeyDetailResponse Response Object
type ListKeyDetailResponse struct {
	KeyInfo        *KeyDetails `json:"key_info,omitempty"`
	HttpStatusCode int         `json:"-"`
}

func (o ListKeyDetailResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ListKeyDetailResponse struct{}"
	}

	return strings.Join([]string{"ListKeyDetailResponse", string(data)}, " ")
}
