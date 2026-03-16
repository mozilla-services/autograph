package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// ShowVersionRequest Request Object
type ShowVersionRequest struct {

	// API版本号
	VersionId string `json:"version_id"`
}

func (o ShowVersionRequest) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ShowVersionRequest struct{}"
	}

	return strings.Join([]string{"ShowVersionRequest", string(data)}, " ")
}
