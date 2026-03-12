package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

type ReplicateKeyRequestBody struct {

	// 待复制的密钥ID，36字节，满足正则匹配“^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$”。 例如：0d0466b0-e727-4d9c-b35d-f84bb474a37f。
	KeyId string `json:"key_id"`

	// 复制密钥的目的区域编码。如cn-north-4。
	ReplicaRegion string `json:"replica_region"`

	// 指定复制出的新密钥的别名。
	KeyAlias string `json:"key_alias"`

	// 指定复制出的新密钥的描述信息。
	KeyDescription *string `json:"key_description,omitempty"`

	// 指定复制出的新密钥的企业多项目ID。 - 用户未开通企业多项目时，不需要输入该字段。 - 用户开通企业多项目时，创建资源可以输入该字段。若用户户不输入该字段，默认创建属于默认企业多项目ID（ID为“0”）的资源。 注意：若用户没有默认企业多项目ID（ID为“0”）下的创建权限，则接口报错。
	EnterpriseProjectId *string `json:"enterprise_project_id,omitempty"`

	// 指定复制出的新密钥的项目ID。
	ReplicaProjectId string `json:"replica_project_id"`

	// 标签列表，key和value键值对的集合。
	Tags *[]TagItem `json:"tags,omitempty"`
}

func (o ReplicateKeyRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ReplicateKeyRequestBody struct{}"
	}

	return strings.Join([]string{"ReplicateKeyRequestBody", string(data)}, " ")
}
