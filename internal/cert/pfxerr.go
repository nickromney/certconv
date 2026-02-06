package cert

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrPFXIncorrectPassword indicates openssl rejected the supplied password.
	ErrPFXIncorrectPassword = errors.New("incorrect password")

	// ErrPFXNotPKCS12 indicates the file is not a valid PKCS#12/PFX container.
	ErrPFXNotPKCS12 = errors.New("file is not a valid PKCS#12/PFX file")

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
