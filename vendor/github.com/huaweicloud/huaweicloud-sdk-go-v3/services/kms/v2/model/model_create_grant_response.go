package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// CreateGrantResponse Response Object
type CreateGrantResponse struct {

	// 授权ID，64字节。
	GrantId        *string `json:"grant_id,omitempty"`
	HttpStatusCode int     `json:"-"`
}

func (o CreateGrantResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CreateGrantResponse struct{}"
	}

	return strings.Join([]string{"CreateGrantResponse", string(data)}, " ")
}
