package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// CreateKmsTagResponse Response Object
type CreateKmsTagResponse struct {
	HttpStatusCode int `json:"-"`
}

func (o CreateKmsTagResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CreateKmsTagResponse struct{}"
	}

	return strings.Join([]string{"CreateKmsTagResponse", string(data)}, " ")
}
