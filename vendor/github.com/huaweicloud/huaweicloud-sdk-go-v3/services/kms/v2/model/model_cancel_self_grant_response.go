package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// CancelSelfGrantResponse Response Object
type CancelSelfGrantResponse struct {
	HttpStatusCode int `json:"-"`
}

func (o CancelSelfGrantResponse) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CancelSelfGrantResponse struct{}"
	}

	return strings.Join([]string{"CancelSelfGrantResponse", string(data)}, " ")
}
