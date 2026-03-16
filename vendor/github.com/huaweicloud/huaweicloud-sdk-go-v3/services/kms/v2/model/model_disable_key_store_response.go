package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// DisableKeyStoreResponse Response Object
type DisableKeyStoreResponse struct {
	Keystore       *KeyStoreStateInfo `json:"keystore,omitempty"`
	HttpStatusCode int                `json:"-"`
}

func (o DisableKeyStoreResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "DisableKeyStoreResponse struct{}"
	}

	return strings.Join([]string{"DisableKeyStoreResponse", string(data)}, " ")
}
