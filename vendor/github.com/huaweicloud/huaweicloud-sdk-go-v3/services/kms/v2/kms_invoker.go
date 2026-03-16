package v2

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/invoker"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2/model"
)

type AssociateAliasInvoker struct {
	*invoker.BaseInvoker
}

func (i *AssociateAliasInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *AssociateAliasInvoker) Invoke() (*model.AssociateAliasResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.AssociateAliasResponse), nil
	}
}

type BatchCreateKmsTagsInvoker struct {
	*invoker.BaseInvoker
}

func (i *BatchCreateKmsTagsInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *BatchCreateKmsTagsInvoker) Invoke() (*model.BatchCreateKmsTagsResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.BatchCreateKmsTagsResponse), nil
	}
}

type CancelGrantInvoker struct {
	*invoker.BaseInvoker
}

func (i *CancelGrantInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *CancelGrantInvoker) Invoke() (*model.CancelGrantResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.CancelGrantResponse), nil
	}
}

type CancelKeyDeletionInvoker struct {
	*invoker.BaseInvoker
}

func (i *CancelKeyDeletionInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *CancelKeyDeletionInvoker) Invoke() (*model.CancelKeyDeletionResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.CancelKeyDeletionResponse), nil
	}
}

type CancelSelfGrantInvoker struct {
	*invoker.BaseInvoker
}

func (i *CancelSelfGrantInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *CancelSelfGrantInvoker) Invoke() (*model.CancelSelfGrantResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.CancelSelfGrantResponse), nil
	}
}

type CreateAliasInvoker struct {
	*invoker.BaseInvoker
}

func (i *CreateAliasInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *CreateAliasInvoker) Invoke() (*model.CreateAliasResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.CreateAliasResponse), nil
	}
}

type CreateDatakeyInvoker struct {
	*invoker.BaseInvoker
}

func (i *CreateDatakeyInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *CreateDatakeyInvoker) Invoke() (*model.CreateDatakeyResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.CreateDatakeyResponse), nil
	}
}

type CreateDatakeyWithoutPlaintextInvoker struct {
	*invoker.BaseInvoker
}

func (i *CreateDatakeyWithoutPlaintextInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *CreateDatakeyWithoutPlaintextInvoker) Invoke() (*model.CreateDatakeyWithoutPlaintextResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.CreateDatakeyWithoutPlaintextResponse), nil
	}
}

type CreateEcDatakeyPairInvoker struct {
	*invoker.BaseInvoker
}

func (i *CreateEcDatakeyPairInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *CreateEcDatakeyPairInvoker) Invoke() (*model.CreateEcDatakeyPairResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.CreateEcDatakeyPairResponse), nil
	}
}

type CreateGrantInvoker struct {
	*invoker.BaseInvoker
}

func (i *CreateGrantInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *CreateGrantInvoker) Invoke() (*model.CreateGrantResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.CreateGrantResponse), nil
	}
}

type CreateKeyInvoker struct {
	*invoker.BaseInvoker
}

func (i *CreateKeyInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *CreateKeyInvoker) Invoke() (*model.CreateKeyResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.CreateKeyResponse), nil
	}
}

type CreateKeyStoreInvoker struct {
	*invoker.BaseInvoker
}

func (i *CreateKeyStoreInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *CreateKeyStoreInvoker) Invoke() (*model.CreateKeyStoreResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.CreateKeyStoreResponse), nil
	}
}

type CreateKmsTagInvoker struct {
	*invoker.BaseInvoker
}

func (i *CreateKmsTagInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *CreateKmsTagInvoker) Invoke() (*model.CreateKmsTagResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.CreateKmsTagResponse), nil
	}
}

type CreateParametersForImportInvoker struct {
	*invoker.BaseInvoker
}

func (i *CreateParametersForImportInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *CreateParametersForImportInvoker) Invoke() (*model.CreateParametersForImportResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.CreateParametersForImportResponse), nil
	}
}

type CreatePinInvoker struct {
	*invoker.BaseInvoker
}

func (i *CreatePinInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *CreatePinInvoker) Invoke() (*model.CreatePinResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.CreatePinResponse), nil
	}
}

type CreateRandomInvoker struct {
	*invoker.BaseInvoker
}

func (i *CreateRandomInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *CreateRandomInvoker) Invoke() (*model.CreateRandomResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.CreateRandomResponse), nil
	}
}

type CreateRsaDatakeyPairInvoker struct {
	*invoker.BaseInvoker
}

func (i *CreateRsaDatakeyPairInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *CreateRsaDatakeyPairInvoker) Invoke() (*model.CreateRsaDatakeyPairResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.CreateRsaDatakeyPairResponse), nil
	}
}

type DecryptDataInvoker struct {
	*invoker.BaseInvoker
}

func (i *DecryptDataInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *DecryptDataInvoker) Invoke() (*model.DecryptDataResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.DecryptDataResponse), nil
	}
}

type DecryptDatakeyInvoker struct {
	*invoker.BaseInvoker
}

func (i *DecryptDatakeyInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *DecryptDatakeyInvoker) Invoke() (*model.DecryptDatakeyResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.DecryptDatakeyResponse), nil
	}
}

type DeleteAliasInvoker struct {
	*invoker.BaseInvoker
}

func (i *DeleteAliasInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *DeleteAliasInvoker) Invoke() (*model.DeleteAliasResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.DeleteAliasResponse), nil
	}
}

type DeleteImportedKeyMaterialInvoker struct {
	*invoker.BaseInvoker
}

func (i *DeleteImportedKeyMaterialInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *DeleteImportedKeyMaterialInvoker) Invoke() (*model.DeleteImportedKeyMaterialResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.DeleteImportedKeyMaterialResponse), nil
	}
}

type DeleteKeyInvoker struct {
	*invoker.BaseInvoker
}

func (i *DeleteKeyInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *DeleteKeyInvoker) Invoke() (*model.DeleteKeyResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.DeleteKeyResponse), nil
	}
}

type DeleteKeyStoreInvoker struct {
	*invoker.BaseInvoker
}

func (i *DeleteKeyStoreInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *DeleteKeyStoreInvoker) Invoke() (*model.DeleteKeyStoreResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.DeleteKeyStoreResponse), nil
	}
}

type DeleteTagInvoker struct {
	*invoker.BaseInvoker
}

func (i *DeleteTagInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *DeleteTagInvoker) Invoke() (*model.DeleteTagResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.DeleteTagResponse), nil
	}
}

type DisableKeyInvoker struct {
	*invoker.BaseInvoker
}

func (i *DisableKeyInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *DisableKeyInvoker) Invoke() (*model.DisableKeyResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.DisableKeyResponse), nil
	}
}

type DisableKeyRotationInvoker struct {
	*invoker.BaseInvoker
}

func (i *DisableKeyRotationInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *DisableKeyRotationInvoker) Invoke() (*model.DisableKeyRotationResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.DisableKeyRotationResponse), nil
	}
}

type DisableKeyStoreInvoker struct {
	*invoker.BaseInvoker
}

func (i *DisableKeyStoreInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *DisableKeyStoreInvoker) Invoke() (*model.DisableKeyStoreResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.DisableKeyStoreResponse), nil
	}
}

type EnableKeyInvoker struct {
	*invoker.BaseInvoker
}

func (i *EnableKeyInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *EnableKeyInvoker) Invoke() (*model.EnableKeyResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.EnableKeyResponse), nil
	}
}

type EnableKeyRotationInvoker struct {
	*invoker.BaseInvoker
}

func (i *EnableKeyRotationInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *EnableKeyRotationInvoker) Invoke() (*model.EnableKeyRotationResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.EnableKeyRotationResponse), nil
	}
}

type EnableKeyStoreInvoker struct {
	*invoker.BaseInvoker
}

func (i *EnableKeyStoreInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *EnableKeyStoreInvoker) Invoke() (*model.EnableKeyStoreResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.EnableKeyStoreResponse), nil
	}
}

type EncryptDataInvoker struct {
	*invoker.BaseInvoker
}

func (i *EncryptDataInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *EncryptDataInvoker) Invoke() (*model.EncryptDataResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.EncryptDataResponse), nil
	}
}

type EncryptDatakeyInvoker struct {
	*invoker.BaseInvoker
}

func (i *EncryptDatakeyInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *EncryptDatakeyInvoker) Invoke() (*model.EncryptDatakeyResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.EncryptDatakeyResponse), nil
	}
}

type GenerateMacInvoker struct {
	*invoker.BaseInvoker
}

func (i *GenerateMacInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *GenerateMacInvoker) Invoke() (*model.GenerateMacResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.GenerateMacResponse), nil
	}
}

type ImportKeyMaterialInvoker struct {
	*invoker.BaseInvoker
}

func (i *ImportKeyMaterialInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ImportKeyMaterialInvoker) Invoke() (*model.ImportKeyMaterialResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ImportKeyMaterialResponse), nil
	}
}

type ListAliasesInvoker struct {
	*invoker.BaseInvoker
}

func (i *ListAliasesInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ListAliasesInvoker) Invoke() (*model.ListAliasesResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ListAliasesResponse), nil
	}
}

type ListGrantsInvoker struct {
	*invoker.BaseInvoker
}

func (i *ListGrantsInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ListGrantsInvoker) Invoke() (*model.ListGrantsResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ListGrantsResponse), nil
	}
}

type ListKeyDetailInvoker struct {
	*invoker.BaseInvoker
}

func (i *ListKeyDetailInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ListKeyDetailInvoker) Invoke() (*model.ListKeyDetailResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ListKeyDetailResponse), nil
	}
}

type ListKeyStoresInvoker struct {
	*invoker.BaseInvoker
}

func (i *ListKeyStoresInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ListKeyStoresInvoker) Invoke() (*model.ListKeyStoresResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ListKeyStoresResponse), nil
	}
}

type ListKeysInvoker struct {
	*invoker.BaseInvoker
}

func (i *ListKeysInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ListKeysInvoker) Invoke() (*model.ListKeysResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ListKeysResponse), nil
	}
}

type ListKmsByTagsInvoker struct {
	*invoker.BaseInvoker
}

func (i *ListKmsByTagsInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ListKmsByTagsInvoker) Invoke() (*model.ListKmsByTagsResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ListKmsByTagsResponse), nil
	}
}

type ListKmsTagsInvoker struct {
	*invoker.BaseInvoker
}

func (i *ListKmsTagsInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ListKmsTagsInvoker) Invoke() (*model.ListKmsTagsResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ListKmsTagsResponse), nil
	}
}

type ListRetirableGrantsInvoker struct {
	*invoker.BaseInvoker
}

func (i *ListRetirableGrantsInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ListRetirableGrantsInvoker) Invoke() (*model.ListRetirableGrantsResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ListRetirableGrantsResponse), nil
	}
}

type ListSupportRegionsInvoker struct {
	*invoker.BaseInvoker
}

func (i *ListSupportRegionsInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ListSupportRegionsInvoker) Invoke() (*model.ListSupportRegionsResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ListSupportRegionsResponse), nil
	}
}

type ReplicateKeyInvoker struct {
	*invoker.BaseInvoker
}

func (i *ReplicateKeyInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ReplicateKeyInvoker) Invoke() (*model.ReplicateKeyResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ReplicateKeyResponse), nil
	}
}

type ShowKeyRotationStatusInvoker struct {
	*invoker.BaseInvoker
}

func (i *ShowKeyRotationStatusInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ShowKeyRotationStatusInvoker) Invoke() (*model.ShowKeyRotationStatusResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ShowKeyRotationStatusResponse), nil
	}
}

type ShowKeyStoreInvoker struct {
	*invoker.BaseInvoker
}

func (i *ShowKeyStoreInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ShowKeyStoreInvoker) Invoke() (*model.ShowKeyStoreResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ShowKeyStoreResponse), nil
	}
}

type ShowKmsTagsInvoker struct {
	*invoker.BaseInvoker
}

func (i *ShowKmsTagsInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ShowKmsTagsInvoker) Invoke() (*model.ShowKmsTagsResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ShowKmsTagsResponse), nil
	}
}

type ShowPublicKeyInvoker struct {
	*invoker.BaseInvoker
}

func (i *ShowPublicKeyInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ShowPublicKeyInvoker) Invoke() (*model.ShowPublicKeyResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ShowPublicKeyResponse), nil
	}
}

type ShowUserInstancesInvoker struct {
	*invoker.BaseInvoker
}

func (i *ShowUserInstancesInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ShowUserInstancesInvoker) Invoke() (*model.ShowUserInstancesResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ShowUserInstancesResponse), nil
	}
}

type ShowUserQuotasInvoker struct {
	*invoker.BaseInvoker
}

func (i *ShowUserQuotasInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ShowUserQuotasInvoker) Invoke() (*model.ShowUserQuotasResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ShowUserQuotasResponse), nil
	}
}

type SignInvoker struct {
	*invoker.BaseInvoker
}

func (i *SignInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *SignInvoker) Invoke() (*model.SignResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.SignResponse), nil
	}
}

type UpdateKeyAliasInvoker struct {
	*invoker.BaseInvoker
}

func (i *UpdateKeyAliasInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *UpdateKeyAliasInvoker) Invoke() (*model.UpdateKeyAliasResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.UpdateKeyAliasResponse), nil
	}
}

type UpdateKeyDescriptionInvoker struct {
	*invoker.BaseInvoker
}

func (i *UpdateKeyDescriptionInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *UpdateKeyDescriptionInvoker) Invoke() (*model.UpdateKeyDescriptionResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.UpdateKeyDescriptionResponse), nil
	}
}

type UpdateKeyRotationIntervalInvoker struct {
	*invoker.BaseInvoker
}

func (i *UpdateKeyRotationIntervalInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *UpdateKeyRotationIntervalInvoker) Invoke() (*model.UpdateKeyRotationIntervalResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.UpdateKeyRotationIntervalResponse), nil
	}
}

type UpdatePrimaryRegionInvoker struct {
	*invoker.BaseInvoker
}

func (i *UpdatePrimaryRegionInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *UpdatePrimaryRegionInvoker) Invoke() (*model.UpdatePrimaryRegionResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.UpdatePrimaryRegionResponse), nil
	}
}

type ValidateSignatureInvoker struct {
	*invoker.BaseInvoker
}

func (i *ValidateSignatureInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ValidateSignatureInvoker) Invoke() (*model.ValidateSignatureResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ValidateSignatureResponse), nil
	}
}

type VerifyMacInvoker struct {
	*invoker.BaseInvoker
}

func (i *VerifyMacInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *VerifyMacInvoker) Invoke() (*model.VerifyMacResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.VerifyMacResponse), nil
	}
}

type ShowVersionInvoker struct {
	*invoker.BaseInvoker
}

func (i *ShowVersionInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ShowVersionInvoker) Invoke() (*model.ShowVersionResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ShowVersionResponse), nil
	}
}

type ShowVersionsInvoker struct {
	*invoker.BaseInvoker
}

func (i *ShowVersionsInvoker) GetBaseInvoker() *invoker.BaseInvoker {
	return i.BaseInvoker
}

func (i *ShowVersionsInvoker) Invoke() (*model.ShowVersionsResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ShowVersionsResponse), nil
	}
}
