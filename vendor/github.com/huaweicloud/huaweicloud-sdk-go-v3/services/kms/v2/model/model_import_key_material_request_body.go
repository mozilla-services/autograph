package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

type ImportKeyMaterialRequestBody struct {

	// 密钥ID，36字节，满足正则匹配“^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$”。 例如：0d0466b0-e727-4d9c-b35d-f84bb474a37f。
	KeyId string `json:"key_id"`

	// 密钥导入令牌，base64格式，满足正则匹配“^[0-9a-zA-Z+/=]{200,6144}$”。
	ImportToken string `json:"import_token"`

	// 加密后的对称密钥材料，base64格式，满足正则匹配“^[0-9a-zA-Z+/=]{344,360}$”。若导入非对称密钥，则该参数为用于加密私钥的临时中间密钥。
	EncryptedKeyMaterial string `json:"encrypted_key_material"`

	// 使用临时中间密钥加密后的私钥，导入非对称密钥需要该参数，base64格式，满足正则匹配“^[0-9a-zA-Z+/=]{200,6144}$”。
	EncryptedPrivatekey *string `json:"encrypted_privatekey,omitempty"`

	// 密钥材料到期时间，时间戳，即从1970年1月1日至该时间的总秒数，KMS会在该时间的24小时内删除密钥材料。 例如：1550291833
	ExpirationTime *int64 `json:"expiration_time,omitempty"`

	// 请求消息序列号，36字节序列号。 例如：919c82d4-8046-4722-9094-35c3c6524cff
	Sequence *string `json:"sequence,omitempty"`
}

func (o ImportKeyMaterialRequestBody) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "ImportKeyMaterialRequestBody struct{}"
	}

	return strings.Join([]string{"ImportKeyMaterialRequestBody", string(data)}, " ")
}
