package cert

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var ErrNotRSA = errors.New("not an RSA key/certificate (no modulus)")

// RSAModulus returns the RSA modulus (hex) for a certificate/key file.
// It supports:
// - PEM certs/combined: openssl x509 -modulus
// - DER certs: openssl x509 -inform DER -modulus
// - RSA private keys: openssl rsa -modulus
// - PEM public keys: openssl rsa -pubin -modulus
func (e *Engine) RSAModulus(ctx context.Context, path string) (string, error) {
	ft, err := DetectType(path)
	if err != nil {
		return "", fmt.Errorf("detect type: %w", err)
	}

	var stdout, stderr []byte
	switch ft {
	case FileTypeCert, FileTypeCombined:
		stdout, stderr, err = e.exec.Run(ctx, "x509", "-in", path, "-noout", "-modulus")
	case FileTypeDER:
		stdout, stderr, err = e.exec.Run(ctx, "x509", "-in", path, "-inform", "DER", "-noout", "-modulus")
	case FileTypeKey:
		stdout, stderr, err = e.exec.Run(ctx, "rsa", "-in", path, "-noout", "-modulus")
	case FileTypePublicKey:
		// Only support PEM public keys here. OpenSSH keys don't have an RSA modulus in this form.
		if !hasPublicKeyMarker(path) {
			return "", ErrNotRSA
		}
		stdout, stderr, err = e.exec.Run(ctx, "rsa", "-pubin", "-in", path, "-noout", "-modulus")
	default:
		return "", fmt.Errorf("unsupported file type: %s", ft)
	}

	// If the context was cancelled (rapid navigation), bubble that up.
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return "", err
		}

		msg := strings.ToLower(strings.TrimSpace(string(stderr)))
		switch {
		case strings.Contains(msg, "non-rsa") ||
			strings.Contains(msg, "not rsa") ||
			strings.Contains(msg, "can't use -modulus") ||
			strings.Contains(msg, "unknown option -modulus") ||
			strings.Contains(msg, "expecting:") && strings.Contains(msg, "rsa"):
			return "", ErrNotRSA
		}
		if strings.TrimSpace(string(stderr)) != "" {
			return "", errors.New(strings.TrimSpace(string(stderr)))
		}
		return "", err
	}

	mod, ok := parseModulus(stdout)
	if !ok || strings.TrimSpace(mod) == "" {
		// If it succeeded but gave no modulus, treat it as non-RSA.
		return "", ErrNotRSA
	}
	return mod, nil
}

func parseModulus(stdout []byte) (string, bool) {
	s := strings.TrimSpace(string(stdout))
	// Expected: "Modulus=ABCDEF..."
	const pfx = "Modulus="
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, pfx) {
			return strings.TrimSpace(strings.TrimPrefix(line, pfx)), true
		}
	}
	return "", false
}

func ModulusDigestsHex(modulusHex string) (sha256Hex string, md5Hex string) {
	b := []byte(strings.TrimSpace(modulusHex))
	sha := sha256.Sum256(b)
	md := md5.Sum(b)
	return hex.EncodeToString(sha[:]), hex.EncodeToString(md[:])
}
