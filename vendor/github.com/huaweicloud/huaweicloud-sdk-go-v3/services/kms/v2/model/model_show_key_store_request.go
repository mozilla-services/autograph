package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ShowKeyStoreRequest Request Object
type ShowKeyStoreRequest struct {

	// 密钥库ID
	KeystoreId string `json:"keystore_id"`
}

func (o ShowKeyStoreRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ShowKeyStoreRequest struct{}"
	}

	return strings.Join([]string{"ShowKeyStoreRequest", string(data)}, " ")
}
