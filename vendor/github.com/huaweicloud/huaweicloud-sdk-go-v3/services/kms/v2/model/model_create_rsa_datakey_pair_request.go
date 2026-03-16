package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// CreateRsaDatakeyPairRequest Request Object
type CreateRsaDatakeyPairRequest struct {
	Body *CreateRsaDatakeyPairRequestBody `json:"body,omitempty"`
}

func (o CreateRsaDatakeyPairRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CreateRsaDatakeyPairRequest struct{}"
	}

	return strings.Join([]string{"CreateRsaDatakeyPairRequest", string(data)}, " ")
}
