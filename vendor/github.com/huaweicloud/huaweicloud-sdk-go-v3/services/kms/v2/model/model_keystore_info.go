package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

type KeystoreInfo struct {

	// 密钥库ID
	KeystoreId *string `json:"keystore_id,omitempty"`

	// 用户域ID
	DomainId *string `json:"domain_id,omitempty"`
}

func (o KeystoreInfo) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "KeystoreInfo struct{}"
	}

	return strings.Join([]string{"KeystoreInfo", string(data)}, " ")
}
