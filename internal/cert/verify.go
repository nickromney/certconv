package cert

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
)

// VerifyChain verifies a certificate against a CA bundle.
func (e *Engine) VerifyChain(ctx context.Context, certPath, caPath string) (*VerifyResult, error) {
	stdout, stderr, err := e.exec.Run(ctx, "verify", "-CAfile", caPath, certPath)
	output := string(stdout)
	if len(stderr) > 0 {
		output += string(stderr)
	}

	result := &VerifyResult{
		Output: strings.TrimSpace(output),
	}

	if err == nil && strings.Contains(output, ": OK") {
		result.Valid = true
		return result, nil
	}

	// Build diagnostic details
	var details []string
	if strings.Contains(output, "expired") || strings.Contains(output, "Expire") {
		details = append(details, "Certificate or CA has expired")
	}
	if strings.Contains(output, "unable to get local issuer") {
		details = append(details, "Certificate issuer not found in CA bundle")
	}
	if strings.Contains(output, "self") && strings.Contains(output, "signed") {
		details = append(details, "Certificate is self-signed")
	}
	result.Details = strings.Join(details, "; ")

	return result, nil
}

// MatchKeyToCert checks whether a private key matches a certificate by comparing
// their derived public keys (works for RSA and EC).
func (e *Engine) MatchKeyToCert(ctx context.Context, certPath, keyPath string) (*MatchResult, error) {
	ft, _ := DetectType(certPath)
	args := []string{"x509", "-in", certPath, "-pubkey", "-noout"}
	if ft == FileTypeDER {
		args = []string{"x509", "-in", certPath, "-inform", "DER", "-pubkey", "-noout"}
	}

	certPub, certStderr, err := e.exec.Run(ctx, args...)
	if err != nil {
		msg := strings.TrimSpace(string(certStderr))
		if msg != "" {
			return nil, fmt.Errorf("read certificate public key: %s", msg)
		}
		return nil, fmt.Errorf("read certificate public key: %w", err)
	}

	keyPub, keyStderr, err := e.exec.Run(ctx, "pkey", "-in", keyPath, "-pubout")
	if err != nil {
		msg := strings.TrimSpace(string(keyStderr))
		if msg != "" {
			return nil, fmt.Errorf("read key public key: %s", msg)
		}
		return nil, fmt.Errorf("read key public key: %w", err)
	}

	certNorm := normalizePEMPayload(string(certPub))
	keyNorm := normalizePEMPayload(string(keyPub))
	if certNorm == "" || keyNorm == "" {
		return nil, fmt.Errorf("failed to normalize public keys for comparison")
	}

	return &MatchResult{
		Match: certNorm == keyNorm,
	}, nil
}

func normalizePEMPayload(s string) string {
	var out strings.Builder
	inPayload := false
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-----BEGIN ") {
			inPayload = true
			continue
		}
		if strings.HasPrefix(line, "-----END ") {
			inPayload = false
			continue
		}
		if !inPayload || line == "" {
			continue
		}
		out.WriteString(line)
	}
	return out.String()
}

// ValidatePEMCert checks that a file is a valid PEM certificate.
func ValidatePEMCert(path string) error {
	hasCert, _, err := scanPEMMarkers(path)
	if err != nil {
		return err
	}
	if !hasCert {
		return fmt.Errorf("not a PEM certificate: %s (expected: -----BEGIN CERTIFICATE-----)", path)
	}
	return nil
}

// ValidatePEMKey checks that a file contains a PEM private key header.
func ValidatePEMKey(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if keyHeaderRE.MatchString(scanner.Text()) {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return fmt.Errorf("not a PEM private key: %s", path)
}
