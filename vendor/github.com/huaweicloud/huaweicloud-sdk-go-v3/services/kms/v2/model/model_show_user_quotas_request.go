package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ShowUserQuotasRequest Request Object
type ShowUserQuotasRequest struct {
}

func (o ShowUserQuotasRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ShowUserQuotasRequest struct{}"
	}

	return strings.Join([]string{"ShowUserQuotasRequest", string(data)}, " ")
}
