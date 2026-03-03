package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// EnableKeyRotationResponse Response Object
type EnableKeyRotationResponse struct {
	HttpStatusCode int `json:"-"`
}

func (o EnableKeyRotationResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "EnableKeyRotationResponse struct{}"
	}

	return strings.Join([]string{"EnableKeyRotationResponse", string(data)}, " ")
}
