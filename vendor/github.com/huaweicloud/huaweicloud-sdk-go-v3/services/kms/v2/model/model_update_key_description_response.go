package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// UpdateKeyDescriptionResponse Response Object
type UpdateKeyDescriptionResponse struct {
	KeyInfo        *KeyDescriptionInfo `json:"key_info,omitempty"`
	HttpStatusCode int                 `json:"-"`
}

func (o UpdateKeyDescriptionResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "UpdateKeyDescriptionResponse struct{}"
	}

	return strings.Join([]string{"UpdateKeyDescriptionResponse", string(data)}, " ")
}
