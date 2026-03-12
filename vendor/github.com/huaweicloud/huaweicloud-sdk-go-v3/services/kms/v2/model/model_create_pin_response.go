package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// CreatePinResponse Response Object
type CreatePinResponse struct {

	// 创建的pin码
	Pin            *string `json:"pin,omitempty"`
	HttpStatusCode int     `json:"-"`
}

func (o CreatePinResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CreatePinResponse struct{}"
	}

	return strings.Join([]string{"CreatePinResponse", string(data)}, " ")
}
