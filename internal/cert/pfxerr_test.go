package cert

import (
	"errors"
	"testing"
)

func TestPfxReadError_ClassifiesIncorrectPassword(t *testing.T) {
	err := pfxReadError(assertErr{}, []byte("Mac verify error: invalid password?"))
	if !IsPFXIncorrectPassword(err) {
		t.Fatalf("expected incorrect password classification, got: %v", err)
	}
}

func TestPfxReadError_ClassifiesNotPKCS12(t *testing.T) {
	err := pfxReadError(assertErr{}, []byte("expecting an asn1 sequence"))
	if err == nil || err.Error() == "" {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, ErrPFXNotPKCS12) {
		t.Fatalf("expected not-pkcs12 classification, got: %v", err)
	}
}

type assertErr struct{}

func (assertErr) Error() string { return "exit status 1" }
