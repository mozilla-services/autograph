package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ImportKeyMaterialResponse Response Object
type ImportKeyMaterialResponse struct {
	HttpStatusCode int `json:"-"`
}

func (o ImportKeyMaterialResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ImportKeyMaterialResponse struct{}"
	}

	return strings.Join([]string{"ImportKeyMaterialResponse", string(data)}, " ")
}
