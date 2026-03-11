package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// DisableKeyStoreRequest Request Object
type DisableKeyStoreRequest struct {

	// 密钥库ID
	KeystoreId string `json:"keystore_id"`
}

func (o DisableKeyStoreRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "DisableKeyStoreRequest struct{}"
	}

	return strings.Join([]string{"DisableKeyStoreRequest", string(data)}, " ")
}
