package cert

import (
	"errors"
	"fmt"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

var (
	// ErrPFXIncorrectPassword indicates openssl rejected the supplied password.
	ErrPFXIncorrectPassword = errors.New("incorrect password")

	// ErrPFXNotPKCS12 indicates the file is not a valid PKCS#12/PFX container.
	ErrPFXNotPKCS12 = errors.New("file is not a valid PKCS#12/PFX file")

	// ErrPFXUnsupportedStructure indicates the PFX is valid, but not in a shape
	// this pure-Go browser path can summarize yet.
	ErrPFXUnsupportedStructure = errors.New("unsupported PKCS#12/PFX structure")

	// ErrPFXLegacyUnsupported indicates OpenSSL could not decrypt a legacy-encrypted PFX.
	// This is commonly seen on OpenSSL 3 when the legacy provider isn't enabled.
	ErrPFXLegacyUnsupported = errors.New("legacy PFX encryption unsupported by OpenSSL")
)

func IsPFXIncorrectPassword(err error) bool {
	return errors.Is(err, ErrPFXIncorrectPassword)
}

func pfxReadError(err error, stderr []byte) error {
	msg := strings.TrimSpace(string(stderr))
	lower := strings.ToLower(msg)

	switch {
	case strings.Contains(lower, "inner_evp_generic_fetch:unsupported") ||
		strings.Contains(lower, "inner_evp_generic_fetch:unsup"):
		if msg != "" {
			return fmt.Errorf("%w: %s", ErrPFXLegacyUnsupported, msg)
		}
		return ErrPFXLegacyUnsupported

	case strings.Contains(lower, "mac verify failure") ||
		strings.Contains(lower, "mac verify error") ||
		strings.Contains(lower, "invalid password") ||
		strings.Contains(lower, "bad decrypt") ||
		strings.Contains(lower, "password") && strings.Contains(lower, "incorrect"):
		if msg != "" {
			return fmt.Errorf("%w: %s", ErrPFXIncorrectPassword, msg)
		}
		return ErrPFXIncorrectPassword

	case strings.Contains(lower, "expecting an asn1 sequence") ||
		strings.Contains(lower, "not a pkcs12") ||
		strings.Contains(lower, "not a pkcs#12") ||
		strings.Contains(lower, "not a pkcs#12") ||
		// LibreSSL/OpenSSL can emit generic ASN.1 decode errors for non-PKCS12 inputs.
		(strings.Contains(lower, "asn1") && (strings.Contains(lower, "wrong tag") ||
			strings.Contains(lower, "nested asn1 error") ||
			strings.Contains(lower, "not enough data") ||
			strings.Contains(lower, "type=pkcs12"))):
		if msg != "" {
			return fmt.Errorf("%w: %s", ErrPFXNotPKCS12, msg)
		}
		return ErrPFXNotPKCS12
	}

	if msg != "" {
		// Prefer stderr over a generic exit status.
		return errors.New(msg)
	}
	return err
}

func classifyPFXBytesError(err error, fallback error) error {
	if err == nil {
		err = fallback
	}
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, pkcs12.ErrIncorrectPassword), errors.Is(err, pkcs12.ErrDecryption):
		return fmt.Errorf("%w: %s", ErrPFXIncorrectPassword, err.Error())
	}

	var notImpl pkcs12.NotImplementedError
	if errors.As(err, &notImpl) {
		return err
	}

	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(msg, "error reading p12 data"),
		strings.Contains(msg, "asn1"):
		return fmt.Errorf("%w: %s", ErrPFXNotPKCS12, err.Error())
	case strings.Contains(msg, "certificate missing"),
		strings.Contains(msg, "private key missing"),
		strings.Contains(msg, "expected exactly one key bag"),
		strings.Contains(msg, "expected exactly one certificate"),
		strings.Contains(msg, "trust store contains"):
		return fmt.Errorf("%w: %s", ErrPFXUnsupportedStructure, err.Error())
	default:
		return err
	}
}
