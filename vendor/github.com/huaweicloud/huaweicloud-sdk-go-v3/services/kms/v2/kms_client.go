package v2

import (
	httpclient "github.com/huaweicloud/huaweicloud-sdk-go-v3/core"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/invoker"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2/model"
)

type KmsClient struct {
	HcClient *httpclient.HcHttpClient
}

func NewKmsClient(hcClient *httpclient.HcHttpClient) *KmsClient {
	return &KmsClient{HcClient: hcClient}
}

func KmsClientBuilder() *httpclient.HcHttpClientBuilder {
	builder := httpclient.NewHcHttpClientBuilder()
	return builder
}

// AssociateAlias
//
// 关联别名。
// 你可以将别名从原密钥关联到另一个新的密钥
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) AssociateAlias(request *model.AssociateAliasRequest) (*model.AssociateAliasResponse, error) {
	requestDef := GenReqDefForAssociateAlias()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.AssociateAliasResponse), nil
	}
}

// AssociateAliasInvoker
func (c *KmsClient) AssociateAliasInvoker(request *model.AssociateAliasRequest) *AssociateAliasInvoker {
	requestDef := GenReqDefForAssociateAlias()
	return &AssociateAliasInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// BatchCreateKmsTags 批量添加删除密钥标签
//
// - 功能介绍：批量添加删除密钥标签。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) BatchCreateKmsTags(request *model.BatchCreateKmsTagsRequest) (*model.BatchCreateKmsTagsResponse, error) {
	requestDef := GenReqDefForBatchCreateKmsTags()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.BatchCreateKmsTagsResponse), nil
	}
}

// BatchCreateKmsTagsInvoker 批量添加删除密钥标签
func (c *KmsClient) BatchCreateKmsTagsInvoker(request *model.BatchCreateKmsTagsRequest) *BatchCreateKmsTagsInvoker {
	requestDef := GenReqDefForBatchCreateKmsTags()
	return &BatchCreateKmsTagsInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// CancelGrant 撤销授权
//
// - 功能介绍：撤销授权，授权用户撤销被授权用户操作密钥的权限。
// - 说明：
//    - 创建密钥的用户才能撤销该密钥授权。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) CancelGrant(request *model.CancelGrantRequest) (*model.CancelGrantResponse, error) {
	requestDef := GenReqDefForCancelGrant()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.CancelGrantResponse), nil
	}
}

// CancelGrantInvoker 撤销授权
func (c *KmsClient) CancelGrantInvoker(request *model.CancelGrantRequest) *CancelGrantInvoker {
	requestDef := GenReqDefForCancelGrant()
	return &CancelGrantInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// CancelKeyDeletion 取消计划删除密钥
//
// - 功能介绍：取消计划删除密钥。
// - 说明：密钥处于“计划删除”状态才能取消计划删除密钥。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) CancelKeyDeletion(request *model.CancelKeyDeletionRequest) (*model.CancelKeyDeletionResponse, error) {
	requestDef := GenReqDefForCancelKeyDeletion()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.CancelKeyDeletionResponse), nil
	}
}

// CancelKeyDeletionInvoker 取消计划删除密钥
func (c *KmsClient) CancelKeyDeletionInvoker(request *model.CancelKeyDeletionRequest) *CancelKeyDeletionInvoker {
	requestDef := GenReqDefForCancelKeyDeletion()
	return &CancelKeyDeletionInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// CancelSelfGrant 退役授权
//
// - 功能介绍：退役授权，表示被授权用户不再具有授权密钥的操作权。
//   例如：用户A授权用户B可以操作密钥A/key，同时授权用户C可以撤销该授权，
//   那么用户A、B、C均可退役该授权，退役授权后，用户B不再可以使用A/key。
// - 须知：
//      可执行退役授权的主体包括：
//    - 创建授权的用户；
//    - 授权中retiring_principal指向的用户；
//    - 当授权的操作列表中包含retire-grant时，grantee_principal指向的用户。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) CancelSelfGrant(request *model.CancelSelfGrantRequest) (*model.CancelSelfGrantResponse, error) {
	requestDef := GenReqDefForCancelSelfGrant()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.CancelSelfGrantResponse), nil
	}
}

// CancelSelfGrantInvoker 退役授权
func (c *KmsClient) CancelSelfGrantInvoker(request *model.CancelSelfGrantRequest) *CancelSelfGrantInvoker {
	requestDef := GenReqDefForCancelSelfGrant()
	return &CancelSelfGrantInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// CreateAlias
//
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) CreateAlias(request *model.CreateAliasRequest) (*model.CreateAliasResponse, error) {
	requestDef := GenReqDefForCreateAlias()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.CreateAliasResponse), nil
	}
}

// CreateAliasInvoker
func (c *KmsClient) CreateAliasInvoker(request *model.CreateAliasRequest) *CreateAliasInvoker {
	requestDef := GenReqDefForCreateAlias()
	return &CreateAliasInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// CreateDatakey 创建数据密钥
//
// - 功能介绍：创建数据密钥，返回结果包含明文和密文。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) CreateDatakey(request *model.CreateDatakeyRequest) (*model.CreateDatakeyResponse, error) {
	requestDef := GenReqDefForCreateDatakey()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.CreateDatakeyResponse), nil
	}
}

// CreateDatakeyInvoker 创建数据密钥
func (c *KmsClient) CreateDatakeyInvoker(request *model.CreateDatakeyRequest) *CreateDatakeyInvoker {
	requestDef := GenReqDefForCreateDatakey()
	return &CreateDatakeyInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// CreateDatakeyWithoutPlaintext 创建不含明文数据密钥
//
// - 功能介绍：创建数据密钥，返回结果只包含密文。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) CreateDatakeyWithoutPlaintext(request *model.CreateDatakeyWithoutPlaintextRequest) (*model.CreateDatakeyWithoutPlaintextResponse, error) {
	requestDef := GenReqDefForCreateDatakeyWithoutPlaintext()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.CreateDatakeyWithoutPlaintextResponse), nil
	}
}

// CreateDatakeyWithoutPlaintextInvoker 创建不含明文数据密钥
func (c *KmsClient) CreateDatakeyWithoutPlaintextInvoker(request *model.CreateDatakeyWithoutPlaintextRequest) *CreateDatakeyWithoutPlaintextInvoker {
	requestDef := GenReqDefForCreateDatakeyWithoutPlaintext()
	return &CreateDatakeyWithoutPlaintextInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// CreateEcDatakeyPair 创建EC数据密钥对
//
// - 功能介绍：创建EC数据密钥对，返回结果包含明文公钥和密文私钥，根据参数决定是否返回明文私钥。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) CreateEcDatakeyPair(request *model.CreateEcDatakeyPairRequest) (*model.CreateEcDatakeyPairResponse, error) {
	requestDef := GenReqDefForCreateEcDatakeyPair()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.CreateEcDatakeyPairResponse), nil
	}
}

// CreateEcDatakeyPairInvoker 创建EC数据密钥对
func (c *KmsClient) CreateEcDatakeyPairInvoker(request *model.CreateEcDatakeyPairRequest) *CreateEcDatakeyPairInvoker {
	requestDef := GenReqDefForCreateEcDatakeyPair()
	return &CreateEcDatakeyPairInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// CreateGrant 创建授权
//
// - 功能介绍：创建授权，被授权用户可以对授权密钥进行操作。
// - 说明：
//    - 服务默认主密钥（密钥别名后缀为“/default”）不可以授权。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) CreateGrant(request *model.CreateGrantRequest) (*model.CreateGrantResponse, error) {
	requestDef := GenReqDefForCreateGrant()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.CreateGrantResponse), nil
	}
}

// CreateGrantInvoker 创建授权
func (c *KmsClient) CreateGrantInvoker(request *model.CreateGrantRequest) *CreateGrantInvoker {
	requestDef := GenReqDefForCreateGrant()
	return &CreateGrantInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// CreateKey 创建密钥
//
// 创建用户主密钥，用户主密钥可以为对称密钥或非对称密钥。
// - 对称密钥为长度为256位AES密钥或者128位SM4密钥，可用于小量数据的加密或者用于加密数据密钥。
// - 非对称密钥可以为RSA密钥对或者ECC密钥对（包含SM2密钥对），可用于加解密数据、数字签名及验签。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) CreateKey(request *model.CreateKeyRequest) (*model.CreateKeyResponse, error) {
	requestDef := GenReqDefForCreateKey()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.CreateKeyResponse), nil
	}
}

// CreateKeyInvoker 创建密钥
func (c *KmsClient) CreateKeyInvoker(request *model.CreateKeyRequest) *CreateKeyInvoker {
	requestDef := GenReqDefForCreateKey()
	return &CreateKeyInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// CreateKeyStore 创建专属密钥库
//
// - \&quot;创建租户专属密钥库，专属密钥库使用DHSM实例作为密钥的存储\&quot;
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) CreateKeyStore(request *model.CreateKeyStoreRequest) (*model.CreateKeyStoreResponse, error) {
	requestDef := GenReqDefForCreateKeyStore()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.CreateKeyStoreResponse), nil
	}
}

// CreateKeyStoreInvoker 创建专属密钥库
func (c *KmsClient) CreateKeyStoreInvoker(request *model.CreateKeyStoreRequest) *CreateKeyStoreInvoker {
	requestDef := GenReqDefForCreateKeyStore()
	return &CreateKeyStoreInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// CreateKmsTag 添加密钥标签
//
// - 功能介绍：添加密钥标签。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) CreateKmsTag(request *model.CreateKmsTagRequest) (*model.CreateKmsTagResponse, error) {
	requestDef := GenReqDefForCreateKmsTag()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.CreateKmsTagResponse), nil
	}
}

// CreateKmsTagInvoker 添加密钥标签
func (c *KmsClient) CreateKmsTagInvoker(request *model.CreateKmsTagRequest) *CreateKmsTagInvoker {
	requestDef := GenReqDefForCreateKmsTag()
	return &CreateKmsTagInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// CreateParametersForImport 获取密钥导入参数
//
// - 功能介绍：获取导入密钥的必要参数，包括密钥导入令牌和密钥加密公钥。
// - 说明：返回的公钥类型默认为RSA_2048。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) CreateParametersForImport(request *model.CreateParametersForImportRequest) (*model.CreateParametersForImportResponse, error) {
	requestDef := GenReqDefForCreateParametersForImport()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.CreateParametersForImportResponse), nil
	}
}

// CreateParametersForImportInvoker 获取密钥导入参数
func (c *KmsClient) CreateParametersForImportInvoker(request *model.CreateParametersForImportRequest) *CreateParametersForImportInvoker {
	requestDef := GenReqDefForCreateParametersForImport()
	return &CreateParametersForImportInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// CreatePin 创建PIN码
//
// - 功能介绍：创建pin码。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) CreatePin(request *model.CreatePinRequest) (*model.CreatePinResponse, error) {
	requestDef := GenReqDefForCreatePin()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.CreatePinResponse), nil
	}
}

// CreatePinInvoker 创建PIN码
func (c *KmsClient) CreatePinInvoker(request *model.CreatePinRequest) *CreatePinInvoker {
	requestDef := GenReqDefForCreatePin()
	return &CreatePinInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// CreateRandom 创建随机数
//
// - 功能介绍：
//   生成8~8192bit范围内的随机数。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) CreateRandom(request *model.CreateRandomRequest) (*model.CreateRandomResponse, error) {
	requestDef := GenReqDefForCreateRandom()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.CreateRandomResponse), nil
	}
}

// CreateRandomInvoker 创建随机数
func (c *KmsClient) CreateRandomInvoker(request *model.CreateRandomRequest) *CreateRandomInvoker {
	requestDef := GenReqDefForCreateRandom()
	return &CreateRandomInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// CreateRsaDatakeyPair 创建RSA数据密钥对
//
// - 功能介绍：创建rsa数据密钥对，返回结果包含明文公钥和密文私钥，根据参数决定是否返回明文私钥。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) CreateRsaDatakeyPair(request *model.CreateRsaDatakeyPairRequest) (*model.CreateRsaDatakeyPairResponse, error) {
	requestDef := GenReqDefForCreateRsaDatakeyPair()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.CreateRsaDatakeyPairResponse), nil
	}
}

// CreateRsaDatakeyPairInvoker 创建RSA数据密钥对
func (c *KmsClient) CreateRsaDatakeyPairInvoker(request *model.CreateRsaDatakeyPairRequest) *CreateRsaDatakeyPairInvoker {
	requestDef := GenReqDefForCreateRsaDatakeyPair()
	return &CreateRsaDatakeyPairInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// DecryptData 解密数据
//
// - 功能介绍：解密数据。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) DecryptData(request *model.DecryptDataRequest) (*model.DecryptDataResponse, error) {
	requestDef := GenReqDefForDecryptData()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.DecryptDataResponse), nil
	}
}

// DecryptDataInvoker 解密数据
func (c *KmsClient) DecryptDataInvoker(request *model.DecryptDataRequest) *DecryptDataInvoker {
	requestDef := GenReqDefForDecryptData()
	return &DecryptDataInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// DecryptDatakey 解密数据密钥
//
// - 功能介绍：解密数据密钥，用指定的主密钥解密数据密钥。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) DecryptDatakey(request *model.DecryptDatakeyRequest) (*model.DecryptDatakeyResponse, error) {
	requestDef := GenReqDefForDecryptDatakey()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.DecryptDatakeyResponse), nil
	}
}

// DecryptDatakeyInvoker 解密数据密钥
func (c *KmsClient) DecryptDatakeyInvoker(request *model.DecryptDatakeyRequest) *DecryptDatakeyInvoker {
	requestDef := GenReqDefForDecryptDatakey()
	return &DecryptDatakeyInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// DeleteAlias
//
// 删除别名
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) DeleteAlias(request *model.DeleteAliasRequest) (*model.DeleteAliasResponse, error) {
	requestDef := GenReqDefForDeleteAlias()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.DeleteAliasResponse), nil
	}
}

// DeleteAliasInvoker
func (c *KmsClient) DeleteAliasInvoker(request *model.DeleteAliasRequest) *DeleteAliasInvoker {
	requestDef := GenReqDefForDeleteAlias()
	return &DeleteAliasInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// DeleteImportedKeyMaterial 删除密钥材料
//
// - 功能介绍：删除密钥材料信息。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) DeleteImportedKeyMaterial(request *model.DeleteImportedKeyMaterialRequest) (*model.DeleteImportedKeyMaterialResponse, error) {
	requestDef := GenReqDefForDeleteImportedKeyMaterial()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.DeleteImportedKeyMaterialResponse), nil
	}
}

// DeleteImportedKeyMaterialInvoker 删除密钥材料
func (c *KmsClient) DeleteImportedKeyMaterialInvoker(request *model.DeleteImportedKeyMaterialRequest) *DeleteImportedKeyMaterialInvoker {
	requestDef := GenReqDefForDeleteImportedKeyMaterial()
	return &DeleteImportedKeyMaterialInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// DeleteKey 计划删除密钥
//
// - 功能介绍：计划多少天后删除密钥，可设置7天～1096天内删除密钥。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) DeleteKey(request *model.DeleteKeyRequest) (*model.DeleteKeyResponse, error) {
	requestDef := GenReqDefForDeleteKey()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.DeleteKeyResponse), nil
	}
}

// DeleteKeyInvoker 计划删除密钥
func (c *KmsClient) DeleteKeyInvoker(request *model.DeleteKeyRequest) *DeleteKeyInvoker {
	requestDef := GenReqDefForDeleteKey()
	return &DeleteKeyInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// DeleteKeyStore 删除专属密钥库
//
// 删除租户专属密钥库
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) DeleteKeyStore(request *model.DeleteKeyStoreRequest) (*model.DeleteKeyStoreResponse, error) {
	requestDef := GenReqDefForDeleteKeyStore()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.DeleteKeyStoreResponse), nil
	}
}

// DeleteKeyStoreInvoker 删除专属密钥库
func (c *KmsClient) DeleteKeyStoreInvoker(request *model.DeleteKeyStoreRequest) *DeleteKeyStoreInvoker {
	requestDef := GenReqDefForDeleteKeyStore()
	return &DeleteKeyStoreInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// DeleteTag 删除密钥标签
//
// - 功能介绍：删除密钥标签。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) DeleteTag(request *model.DeleteTagRequest) (*model.DeleteTagResponse, error) {
	requestDef := GenReqDefForDeleteTag()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.DeleteTagResponse), nil
	}
}

// DeleteTagInvoker 删除密钥标签
func (c *KmsClient) DeleteTagInvoker(request *model.DeleteTagRequest) *DeleteTagInvoker {
	requestDef := GenReqDefForDeleteTag()
	return &DeleteTagInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// DisableKey 禁用密钥
//
// - 功能介绍：禁用密钥，密钥禁用后不可以使用。
// - 说明：密钥为启用状态才能禁用密钥。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) DisableKey(request *model.DisableKeyRequest) (*model.DisableKeyResponse, error) {
	requestDef := GenReqDefForDisableKey()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.DisableKeyResponse), nil
	}
}

// DisableKeyInvoker 禁用密钥
func (c *KmsClient) DisableKeyInvoker(request *model.DisableKeyRequest) *DisableKeyInvoker {
	requestDef := GenReqDefForDisableKey()
	return &DisableKeyInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// DisableKeyRotation 关闭密钥轮换
//
// - 功能介绍：关闭用户主密钥轮换。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) DisableKeyRotation(request *model.DisableKeyRotationRequest) (*model.DisableKeyRotationResponse, error) {
	requestDef := GenReqDefForDisableKeyRotation()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.DisableKeyRotationResponse), nil
	}
}

// DisableKeyRotationInvoker 关闭密钥轮换
func (c *KmsClient) DisableKeyRotationInvoker(request *model.DisableKeyRotationRequest) *DisableKeyRotationInvoker {
	requestDef := GenReqDefForDisableKeyRotation()
	return &DisableKeyRotationInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// DisableKeyStore 禁用专属密钥库
//
// 禁用租户专属密钥库
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) DisableKeyStore(request *model.DisableKeyStoreRequest) (*model.DisableKeyStoreResponse, error) {
	requestDef := GenReqDefForDisableKeyStore()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.DisableKeyStoreResponse), nil
	}
}

// DisableKeyStoreInvoker 禁用专属密钥库
func (c *KmsClient) DisableKeyStoreInvoker(request *model.DisableKeyStoreRequest) *DisableKeyStoreInvoker {
	requestDef := GenReqDefForDisableKeyStore()
	return &DisableKeyStoreInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// EnableKey 启用密钥
//
// - 功能介绍：启用密钥，密钥启用后才可以使用。
// - 说明：密钥为禁用状态才能启用密钥。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) EnableKey(request *model.EnableKeyRequest) (*model.EnableKeyResponse, error) {
	requestDef := GenReqDefForEnableKey()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.EnableKeyResponse), nil
	}
}

// EnableKeyInvoker 启用密钥
func (c *KmsClient) EnableKeyInvoker(request *model.EnableKeyRequest) *EnableKeyInvoker {
	requestDef := GenReqDefForEnableKey()
	return &EnableKeyInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// EnableKeyRotation 开启密钥轮换
//
// - 功能介绍：开启用户主密钥轮换。
// - 说明：
//   - 开启密钥轮换后，默认轮换间隔时间为365天。
//   - 默认主密钥及外部导入密钥不支持轮换操作。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) EnableKeyRotation(request *model.EnableKeyRotationRequest) (*model.EnableKeyRotationResponse, error) {
	requestDef := GenReqDefForEnableKeyRotation()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.EnableKeyRotationResponse), nil
	}
}

// EnableKeyRotationInvoker 开启密钥轮换
func (c *KmsClient) EnableKeyRotationInvoker(request *model.EnableKeyRotationRequest) *EnableKeyRotationInvoker {
	requestDef := GenReqDefForEnableKeyRotation()
	return &EnableKeyRotationInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// EnableKeyStore 启用专属密钥库
//
// 启用租户专属密钥库
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) EnableKeyStore(request *model.EnableKeyStoreRequest) (*model.EnableKeyStoreResponse, error) {
	requestDef := GenReqDefForEnableKeyStore()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.EnableKeyStoreResponse), nil
	}
}

// EnableKeyStoreInvoker 启用专属密钥库
func (c *KmsClient) EnableKeyStoreInvoker(request *model.EnableKeyStoreRequest) *EnableKeyStoreInvoker {
	requestDef := GenReqDefForEnableKeyStore()
	return &EnableKeyStoreInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// EncryptData 加密数据
//
// - 功能介绍：加密数据，用指定的用户主密钥加密数据。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) EncryptData(request *model.EncryptDataRequest) (*model.EncryptDataResponse, error) {
	requestDef := GenReqDefForEncryptData()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.EncryptDataResponse), nil
	}
}

// EncryptDataInvoker 加密数据
func (c *KmsClient) EncryptDataInvoker(request *model.EncryptDataRequest) *EncryptDataInvoker {
	requestDef := GenReqDefForEncryptData()
	return &EncryptDataInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// EncryptDatakey 加密数据密钥
//
// - 功能介绍：加密数据密钥，用指定的主密钥加密数据密钥。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) EncryptDatakey(request *model.EncryptDatakeyRequest) (*model.EncryptDatakeyResponse, error) {
	requestDef := GenReqDefForEncryptDatakey()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.EncryptDatakeyResponse), nil
	}
}

// EncryptDatakeyInvoker 加密数据密钥
func (c *KmsClient) EncryptDatakeyInvoker(request *model.EncryptDatakeyRequest) *EncryptDatakeyInvoker {
	requestDef := GenReqDefForEncryptDatakey()
	return &EncryptDatakeyInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// GenerateMac 生成消息验证码
//
// 功能介绍：生成消息验证码
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) GenerateMac(request *model.GenerateMacRequest) (*model.GenerateMacResponse, error) {
	requestDef := GenReqDefForGenerateMac()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.GenerateMacResponse), nil
	}
}

// GenerateMacInvoker 生成消息验证码
func (c *KmsClient) GenerateMacInvoker(request *model.GenerateMacRequest) *GenerateMacInvoker {
	requestDef := GenReqDefForGenerateMac()
	return &GenerateMacInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ImportKeyMaterial 导入密钥材料
//
// - 功能介绍：导入密钥材料。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ImportKeyMaterial(request *model.ImportKeyMaterialRequest) (*model.ImportKeyMaterialResponse, error) {
	requestDef := GenReqDefForImportKeyMaterial()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ImportKeyMaterialResponse), nil
	}
}

// ImportKeyMaterialInvoker 导入密钥材料
func (c *KmsClient) ImportKeyMaterialInvoker(request *model.ImportKeyMaterialRequest) *ImportKeyMaterialInvoker {
	requestDef := GenReqDefForImportKeyMaterial()
	return &ImportKeyMaterialInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ListAliases
//
// 查询一个密钥关联的所有别名
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ListAliases(request *model.ListAliasesRequest) (*model.ListAliasesResponse, error) {
	requestDef := GenReqDefForListAliases()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ListAliasesResponse), nil
	}
}

// ListAliasesInvoker
func (c *KmsClient) ListAliasesInvoker(request *model.ListAliasesRequest) *ListAliasesInvoker {
	requestDef := GenReqDefForListAliases()
	return &ListAliasesInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ListGrants 查询授权列表
//
// - 功能介绍：查询密钥的授权列表。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ListGrants(request *model.ListGrantsRequest) (*model.ListGrantsResponse, error) {
	requestDef := GenReqDefForListGrants()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ListGrantsResponse), nil
	}
}

// ListGrantsInvoker 查询授权列表
func (c *KmsClient) ListGrantsInvoker(request *model.ListGrantsRequest) *ListGrantsInvoker {
	requestDef := GenReqDefForListGrants()
	return &ListGrantsInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ListKeyDetail 查询密钥信息
//
// - 功能介绍：查询密钥详细信息。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ListKeyDetail(request *model.ListKeyDetailRequest) (*model.ListKeyDetailResponse, error) {
	requestDef := GenReqDefForListKeyDetail()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ListKeyDetailResponse), nil
	}
}

// ListKeyDetailInvoker 查询密钥信息
func (c *KmsClient) ListKeyDetailInvoker(request *model.ListKeyDetailRequest) *ListKeyDetailInvoker {
	requestDef := GenReqDefForListKeyDetail()
	return &ListKeyDetailInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ListKeyStores 查询专属密钥库列表
//
// 查询租户专属密钥库列表
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ListKeyStores(request *model.ListKeyStoresRequest) (*model.ListKeyStoresResponse, error) {
	requestDef := GenReqDefForListKeyStores()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ListKeyStoresResponse), nil
	}
}

// ListKeyStoresInvoker 查询专属密钥库列表
func (c *KmsClient) ListKeyStoresInvoker(request *model.ListKeyStoresRequest) *ListKeyStoresInvoker {
	requestDef := GenReqDefForListKeyStores()
	return &ListKeyStoresInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ListKeys 查询密钥列表
//
// - 功能介绍：查询用户所有密钥列表。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ListKeys(request *model.ListKeysRequest) (*model.ListKeysResponse, error) {
	requestDef := GenReqDefForListKeys()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ListKeysResponse), nil
	}
}

// ListKeysInvoker 查询密钥列表
func (c *KmsClient) ListKeysInvoker(request *model.ListKeysRequest) *ListKeysInvoker {
	requestDef := GenReqDefForListKeys()
	return &ListKeysInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ListKmsByTags 查询密钥实例
//
// - 功能介绍：查询密钥实例。通过标签过滤，查询指定用户主密钥的详细信息。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ListKmsByTags(request *model.ListKmsByTagsRequest) (*model.ListKmsByTagsResponse, error) {
	requestDef := GenReqDefForListKmsByTags()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ListKmsByTagsResponse), nil
	}
}

// ListKmsByTagsInvoker 查询密钥实例
func (c *KmsClient) ListKmsByTagsInvoker(request *model.ListKmsByTagsRequest) *ListKmsByTagsInvoker {
	requestDef := GenReqDefForListKmsByTags()
	return &ListKmsByTagsInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ListKmsTags 查询项目标签
//
// - 功能介绍：查询用户在指定项目下的所有标签集合。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ListKmsTags(request *model.ListKmsTagsRequest) (*model.ListKmsTagsResponse, error) {
	requestDef := GenReqDefForListKmsTags()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ListKmsTagsResponse), nil
	}
}

// ListKmsTagsInvoker 查询项目标签
func (c *KmsClient) ListKmsTagsInvoker(request *model.ListKmsTagsRequest) *ListKmsTagsInvoker {
	requestDef := GenReqDefForListKmsTags()
	return &ListKmsTagsInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ListRetirableGrants 查询可退役授权列表
//
// - 功能介绍：查询用户可以退役的授权列表。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ListRetirableGrants(request *model.ListRetirableGrantsRequest) (*model.ListRetirableGrantsResponse, error) {
	requestDef := GenReqDefForListRetirableGrants()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ListRetirableGrantsResponse), nil
	}
}

// ListRetirableGrantsInvoker 查询可退役授权列表
func (c *KmsClient) ListRetirableGrantsInvoker(request *model.ListRetirableGrantsRequest) *ListRetirableGrantsInvoker {
	requestDef := GenReqDefForListRetirableGrants()
	return &ListRetirableGrantsInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ListSupportRegions 查询跨区域密钥所支持的区域
//
// - 功能介绍：查询跨区域密钥所支持的区域。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ListSupportRegions(request *model.ListSupportRegionsRequest) (*model.ListSupportRegionsResponse, error) {
	requestDef := GenReqDefForListSupportRegions()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ListSupportRegionsResponse), nil
	}
}

// ListSupportRegionsInvoker 查询跨区域密钥所支持的区域
func (c *KmsClient) ListSupportRegionsInvoker(request *model.ListSupportRegionsRequest) *ListSupportRegionsInvoker {
	requestDef := GenReqDefForListSupportRegions()
	return &ListSupportRegionsInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ReplicateKey 复制密钥到指定区域
//
// 将本区域的密钥复制到指定区域。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ReplicateKey(request *model.ReplicateKeyRequest) (*model.ReplicateKeyResponse, error) {
	requestDef := GenReqDefForReplicateKey()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ReplicateKeyResponse), nil
	}
}

// ReplicateKeyInvoker 复制密钥到指定区域
func (c *KmsClient) ReplicateKeyInvoker(request *model.ReplicateKeyRequest) *ReplicateKeyInvoker {
	requestDef := GenReqDefForReplicateKey()
	return &ReplicateKeyInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ShowKeyRotationStatus 查询密钥轮换状态
//
// - 功能介绍：查询用户主密钥轮换状态。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ShowKeyRotationStatus(request *model.ShowKeyRotationStatusRequest) (*model.ShowKeyRotationStatusResponse, error) {
	requestDef := GenReqDefForShowKeyRotationStatus()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ShowKeyRotationStatusResponse), nil
	}
}

// ShowKeyRotationStatusInvoker 查询密钥轮换状态
func (c *KmsClient) ShowKeyRotationStatusInvoker(request *model.ShowKeyRotationStatusRequest) *ShowKeyRotationStatusInvoker {
	requestDef := GenReqDefForShowKeyRotationStatus()
	return &ShowKeyRotationStatusInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ShowKeyStore 获取专属密钥库
//
// 获取租户专属密钥库
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ShowKeyStore(request *model.ShowKeyStoreRequest) (*model.ShowKeyStoreResponse, error) {
	requestDef := GenReqDefForShowKeyStore()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ShowKeyStoreResponse), nil
	}
}

// ShowKeyStoreInvoker 获取专属密钥库
func (c *KmsClient) ShowKeyStoreInvoker(request *model.ShowKeyStoreRequest) *ShowKeyStoreInvoker {
	requestDef := GenReqDefForShowKeyStore()
	return &ShowKeyStoreInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ShowKmsTags 查询密钥标签
//
// - 功能介绍：查询密钥标签。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ShowKmsTags(request *model.ShowKmsTagsRequest) (*model.ShowKmsTagsResponse, error) {
	requestDef := GenReqDefForShowKmsTags()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ShowKmsTagsResponse), nil
	}
}

// ShowKmsTagsInvoker 查询密钥标签
func (c *KmsClient) ShowKmsTagsInvoker(request *model.ShowKmsTagsRequest) *ShowKmsTagsInvoker {
	requestDef := GenReqDefForShowKmsTags()
	return &ShowKmsTagsInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ShowPublicKey 查询公钥信息
//
// - 查询用户指定非对称密钥的公钥信息。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ShowPublicKey(request *model.ShowPublicKeyRequest) (*model.ShowPublicKeyResponse, error) {
	requestDef := GenReqDefForShowPublicKey()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ShowPublicKeyResponse), nil
	}
}

// ShowPublicKeyInvoker 查询公钥信息
func (c *KmsClient) ShowPublicKeyInvoker(request *model.ShowPublicKeyRequest) *ShowPublicKeyInvoker {
	requestDef := GenReqDefForShowPublicKey()
	return &ShowPublicKeyInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ShowUserInstances 查询实例数
//
// - 功能介绍：查询实例数，获取用户已经创建的用户主密钥数量。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ShowUserInstances(request *model.ShowUserInstancesRequest) (*model.ShowUserInstancesResponse, error) {
	requestDef := GenReqDefForShowUserInstances()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ShowUserInstancesResponse), nil
	}
}

// ShowUserInstancesInvoker 查询实例数
func (c *KmsClient) ShowUserInstancesInvoker(request *model.ShowUserInstancesRequest) *ShowUserInstancesInvoker {
	requestDef := GenReqDefForShowUserInstances()
	return &ShowUserInstancesInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ShowUserQuotas 查询配额
//
// - 功能介绍：查询配额，查询用户可以创建的用户主密钥配额总数及当前使用量信息。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ShowUserQuotas(request *model.ShowUserQuotasRequest) (*model.ShowUserQuotasResponse, error) {
	requestDef := GenReqDefForShowUserQuotas()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ShowUserQuotasResponse), nil
	}
}

// ShowUserQuotasInvoker 查询配额
func (c *KmsClient) ShowUserQuotasInvoker(request *model.ShowUserQuotasRequest) *ShowUserQuotasInvoker {
	requestDef := GenReqDefForShowUserQuotas()
	return &ShowUserQuotasInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// Sign 签名数据
//
// - 功能介绍：使用非对称密钥的私钥对消息或消息摘要进行数字签名。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) Sign(request *model.SignRequest) (*model.SignResponse, error) {
	requestDef := GenReqDefForSign()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.SignResponse), nil
	}
}

// SignInvoker 签名数据
func (c *KmsClient) SignInvoker(request *model.SignRequest) *SignInvoker {
	requestDef := GenReqDefForSign()
	return &SignInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// UpdateKeyAlias 修改密钥别名
//
// - 功能介绍：修改用户主密钥别名。
// - 说明：
//    - 服务默认主密钥（密钥别名后缀为“/default”）不可以修改。
//    - 密钥处于“计划删除”状态，密钥别名不可以修改。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) UpdateKeyAlias(request *model.UpdateKeyAliasRequest) (*model.UpdateKeyAliasResponse, error) {
	requestDef := GenReqDefForUpdateKeyAlias()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.UpdateKeyAliasResponse), nil
	}
}

// UpdateKeyAliasInvoker 修改密钥别名
func (c *KmsClient) UpdateKeyAliasInvoker(request *model.UpdateKeyAliasRequest) *UpdateKeyAliasInvoker {
	requestDef := GenReqDefForUpdateKeyAlias()
	return &UpdateKeyAliasInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// UpdateKeyDescription 修改密钥描述
//
// - 功能介绍：修改用户主密钥描述信息。
// - 说明：
//    - 服务默认主密钥（密钥别名后缀为“/default”）不可以修改。
//    - 密钥处于“计划删除”状态，密钥描述不可以修改。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) UpdateKeyDescription(request *model.UpdateKeyDescriptionRequest) (*model.UpdateKeyDescriptionResponse, error) {
	requestDef := GenReqDefForUpdateKeyDescription()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.UpdateKeyDescriptionResponse), nil
	}
}

// UpdateKeyDescriptionInvoker 修改密钥描述
func (c *KmsClient) UpdateKeyDescriptionInvoker(request *model.UpdateKeyDescriptionRequest) *UpdateKeyDescriptionInvoker {
	requestDef := GenReqDefForUpdateKeyDescription()
	return &UpdateKeyDescriptionInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// UpdateKeyRotationInterval 修改密钥轮换周期
//
// - 功能介绍：修改用户主密钥轮换周期。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) UpdateKeyRotationInterval(request *model.UpdateKeyRotationIntervalRequest) (*model.UpdateKeyRotationIntervalResponse, error) {
	requestDef := GenReqDefForUpdateKeyRotationInterval()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.UpdateKeyRotationIntervalResponse), nil
	}
}

// UpdateKeyRotationIntervalInvoker 修改密钥轮换周期
func (c *KmsClient) UpdateKeyRotationIntervalInvoker(request *model.UpdateKeyRotationIntervalRequest) *UpdateKeyRotationIntervalInvoker {
	requestDef := GenReqDefForUpdateKeyRotationInterval()
	return &UpdateKeyRotationIntervalInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// UpdatePrimaryRegion 修改密钥所属的主区域
//
// 修改密钥所属的主区域。修改后当前区域会变为副本区域。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) UpdatePrimaryRegion(request *model.UpdatePrimaryRegionRequest) (*model.UpdatePrimaryRegionResponse, error) {
	requestDef := GenReqDefForUpdatePrimaryRegion()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.UpdatePrimaryRegionResponse), nil
	}
}

// UpdatePrimaryRegionInvoker 修改密钥所属的主区域
func (c *KmsClient) UpdatePrimaryRegionInvoker(request *model.UpdatePrimaryRegionRequest) *UpdatePrimaryRegionInvoker {
	requestDef := GenReqDefForUpdatePrimaryRegion()
	return &UpdatePrimaryRegionInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ValidateSignature 验证签名
//
// - 功能介绍：使用非对称密钥的私钥对消息或消息摘要进行签名验证。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ValidateSignature(request *model.ValidateSignatureRequest) (*model.ValidateSignatureResponse, error) {
	requestDef := GenReqDefForValidateSignature()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ValidateSignatureResponse), nil
	}
}

// ValidateSignatureInvoker 验证签名
func (c *KmsClient) ValidateSignatureInvoker(request *model.ValidateSignatureRequest) *ValidateSignatureInvoker {
	requestDef := GenReqDefForValidateSignature()
	return &ValidateSignatureInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// VerifyMac 校验消息验证码
//
// 功能介绍：校验消息验证码
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) VerifyMac(request *model.VerifyMacRequest) (*model.VerifyMacResponse, error) {
	requestDef := GenReqDefForVerifyMac()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.VerifyMacResponse), nil
	}
}

// VerifyMacInvoker 校验消息验证码
func (c *KmsClient) VerifyMacInvoker(request *model.VerifyMacRequest) *VerifyMacInvoker {
	requestDef := GenReqDefForVerifyMac()
	return &VerifyMacInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ShowVersion 查询指定版本信息
//
// - 功能介绍：查指定API版本信息。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ShowVersion(request *model.ShowVersionRequest) (*model.ShowVersionResponse, error) {
	requestDef := GenReqDefForShowVersion()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ShowVersionResponse), nil
	}
}

// ShowVersionInvoker 查询指定版本信息
func (c *KmsClient) ShowVersionInvoker(request *model.ShowVersionRequest) *ShowVersionInvoker {
	requestDef := GenReqDefForShowVersion()
	return &ShowVersionInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}

// ShowVersions 查询版本信息列表
//
// - 功能介绍：查询API版本信息列表。
//
// Please refer to HUAWEI cloud API Explorer for details.
func (c *KmsClient) ShowVersions(request *model.ShowVersionsRequest) (*model.ShowVersionsResponse, error) {
	requestDef := GenReqDefForShowVersions()

	if resp, err := c.HcClient.Sync(request, requestDef); err != nil {
		return nil, err
	} else {
		return resp.(*model.ShowVersionsResponse), nil
	}
}

// ShowVersionsInvoker 查询版本信息列表
func (c *KmsClient) ShowVersionsInvoker(request *model.ShowVersionsRequest) *ShowVersionsInvoker {
	requestDef := GenReqDefForShowVersions()
	return &ShowVersionsInvoker{invoker.NewBaseInvoker(c.HcClient, request, requestDef)}
}
