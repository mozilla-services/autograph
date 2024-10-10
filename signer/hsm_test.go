package signer

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/miekg/pkcs11"
	"github.com/mozilla-services/autograph/crypto11"
	"github.com/mozilla-services/autograph/internal/mockpkcs11"
)

func TestUnlimitedBytesRandReader(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockCtx := mockpkcs11.NewMockPKCS11Context(ctrl)
	defer ctrl.Finish()

	slot := uint(0)
	session := pkcs11.SessionHandle(0)
	randBytes := make([]byte, 1024)	
	mockCtx.EXPECT().Initialize().Return(nil).Times(1)
	mockCtx.EXPECT().GetSlotList(true).Return([]uint{slot}, nil).Times(2)
	mockCtx.EXPECT().GetTokenInfo(slot).Return(pkcs11.TokenInfo{}, nil).Times(1)
	mockCtx.EXPECT().OpenSession(slot, uint(6)).Return(session, nil).Times(2)
	mockCtx.EXPECT().GenerateRandom(session, 1024).Return(randBytes, nil).Times(2)
	// these ones are called as part of Close(), not as part of our actual testing
	mockCtx.EXPECT().CloseSession(session).Return(nil).Times(1)

	mockFactory := mockedPKCS11ContextFactory(mockCtx)
	crypto11.Configure(&crypto11.PKCS11Config{}, mockFactory)
	defer crypto11.Close()

	ubrr := new(UnlimitedBytesRandReader)
	result := make([]byte, 2048)
	n, err := ubrr.Read(result)
	if err != nil {
		t.Fatalf("UnlimitedBytesRandReader.Read failed: %v", err)
	}
	if n != 2048 {
		t.Fatalf("failed to read 2048 bytes, read %d instead", n)
	}
}
