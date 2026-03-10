package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ListKeyStoresResponse Response Object
type ListKeyStoresResponse struct {

	// 密钥库总数
	Total *int32 `json:"total,omitempty"`

	// 密钥详情列表。详情参见KeystoreDetails
	Keystores      *[]KeystoreDetails `json:"keystores,omitempty"`
	HttpStatusCode int                `json:"-"`
}

func (o ListKeyStoresResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ListKeyStoresResponse struct{}"
	}

	return strings.Join([]string{"ListKeyStoresResponse", string(data)}, " ")
}
