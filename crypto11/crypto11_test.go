package crypto11

import (
	"errors"
	"testing"
)

func TestFailedFactoryFuncDoesntCausePanics(t *testing.T) {
	expectedErr := errors.New("cool error")
	_, err := Configure(&PKCS11Config{Path: "/nonexistent"}, func(ctx *PKCS11Config) (PKCS11Context, error) {
		return nil, expectedErr
	})
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}
