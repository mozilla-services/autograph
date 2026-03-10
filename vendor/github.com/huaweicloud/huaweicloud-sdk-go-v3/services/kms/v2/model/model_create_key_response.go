package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// CreateKeyResponse Response Object
type CreateKeyResponse struct {
	KeyInfo        *KeKInfo `json:"key_info,omitempty"`
	HttpStatusCode int      `json:"-"`
}

func (o CreateKeyResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CreateKeyResponse struct{}"
	}

	return strings.Join([]string{"CreateKeyResponse", string(data)}, " ")
}
