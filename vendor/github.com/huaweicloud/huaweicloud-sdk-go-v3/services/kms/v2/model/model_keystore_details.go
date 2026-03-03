package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

// KeystoreDetails 密钥库详情
type KeystoreDetails struct {

	// 密钥库ID
	KeystoreId *string `json:"keystore_id,omitempty"`

	// 用户域ID
	DomainId *string `json:"domain_id,omitempty"`

	// 密钥库别名
	KeystoreAlias *string `json:"keystore_alias,omitempty"`

	// 密钥库类型
	KeystoreType *string `json:"keystore_type,omitempty"`

	// DHSM集群id，要求集群当前未创建专属密钥库
	HsmClusterId *string `json:"hsm_cluster_id,omitempty"`

	// 集群ID。当类型为DEFAULT时，cluster_id为”0”。当类型为DHSM时，cluster_id为hsm_cluster_id。当类型为CDMS时，默认密码卡集群，集群ID为“1”。自定义密码卡集群，为cdms_cluster_id
	ClusterId *string `json:"cluster_id,omitempty"`

	// 密钥库创建时间，UTC时间戳。
	CreateTime *string `json:"create_time,omitempty"`
}

func (o KeystoreDetails) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "KeystoreDetails struct{}"
	}

	return strings.Join([]string{"KeystoreDetails", string(data)}, " ")
}
