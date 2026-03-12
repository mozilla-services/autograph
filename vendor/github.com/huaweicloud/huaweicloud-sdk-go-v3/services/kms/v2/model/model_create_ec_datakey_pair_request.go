package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// CreateEcDatakeyPairRequest Request Object
type CreateEcDatakeyPairRequest struct {
	Body *CreateEcDatakeyPairRequestBody `json:"body,omitempty"`
}

func (o CreateEcDatakeyPairRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "CreateEcDatakeyPairRequest struct{}"
	}

	return strings.Join([]string{"CreateEcDatakeyPairRequest", string(data)}, " ")
}
