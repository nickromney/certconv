package cert

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ToPFX converts a PEM cert + key to PKCS#12/PFX format.
func (e *Engine) ToPFX(ctx context.Context, certPath, keyPath, outputPath, password, caPath string) error {
	if err := ValidatePEMCert(certPath); err != nil {
		return err
	}
	if err := ValidatePEMKey(keyPath); err != nil {
		return err
	}
	if err := ensureNotExists(outputPath); err != nil {
		return err
	}

	// Check key matches cert
	m, err := e.MatchKeyToCert(ctx, certPath, keyPath)
	if err != nil {
		return fmt.Errorf("match check: %w", err)
	}
	if !m.Match {
		return fmt.Errorf("private key does NOT match certificate")
	}

	args := []string{"pkcs12", "-export", "-out", outputPath, "-inkey", keyPath, "-in", certPath}
	if caPath != "" {
		args = append(args, "-certfile", caPath)
	}
	args = append(args, "-passout", "pass:"+password)

	tmp, err := newTempPath(outputPath)
	if err != nil {
		return fmt.Errorf("create PFX temp file: %w", err)
	}
	defer os.Remove(tmp)

	// Write to temp path to guarantee we never overwrite existing outputs.
	args[3] = tmp // "-out", tmp

	_, _, err = e.runPKCS12(ctx, args...)
	if err != nil {
		return fmt.Errorf("create PFX: %w", err)
	}
	if err := commitTempFile(tmp, outputPath, 0o600); err != nil {
		return err
	}
	return nil
}

// FromPFX extracts cert, key, and optionally CA certs from a PFX file.
func (e *Engine) FromPFX(ctx context.Context, inputPath, outputDir, password string) (*FromPFXResult, error) {
	// Validate PFX
	_, stderr, err := e.runPKCS12(ctx, "pkcs12", "-in", inputPath, "-noout", "-passin", "pass:"+password)
	if err != nil {
		perr := pfxReadError(err, stderr)
		switch {
		case IsPFXIncorrectPassword(perr):
			return nil, fmt.Errorf("invalid PFX or wrong password: incorrect password")
		case errors.Is(perr, ErrPFXNotPKCS12):
			return nil, fmt.Errorf("file is not a valid PKCS#12/PFX file")
		case errors.Is(perr, ErrPFXLegacyUnsupported):
			return nil, fmt.Errorf("cannot read PFX: uses legacy encryption unsupported by OpenSSL (try enabling the legacy provider)")
		default:
			return nil, fmt.Errorf("invalid PFX: %s", strings.TrimSpace(perr.Error()))
		}
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	base := strings.TrimSuffix(filepath.Base(inputPath), filepath.Ext(inputPath))
	result := &FromPFXResult{
		CertFile: filepath.Join(outputDir, base+".crt"),
		KeyFile:  filepath.Join(outputDir, base+".key"),
	}
	// Never overwrite existing outputs.
	if err := ensureNotExists(result.CertFile); err != nil {
		return nil, err
	}
	if err := ensureNotExists(result.KeyFile); err != nil {
		return nil, err
	}

	passArgs := []string{"-passin", "pass:" + password}

	// Extract certificate
	tmpCert, err := newTempPath(result.CertFile)
	if err != nil {
		return nil, fmt.Errorf("create temp cert file: %w", err)
	}
	defer os.Remove(tmpCert)
	certArgs := append([]string{"pkcs12", "-in", inputPath, "-clcerts", "-nokeys"}, passArgs...)
	certArgs = append(certArgs, "-out", tmpCert)
	if _, _, err := e.runPKCS12(ctx, certArgs...); err != nil {
		return nil, fmt.Errorf("extract certificate: %w", err)
	}
	if err := commitTempFile(tmpCert, result.CertFile, 0o644); err != nil {
		return nil, err
	}

	// Extract private key
	tmpKey, err := newTempPath(result.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("create temp key file: %w", err)
	}
	defer os.Remove(tmpKey)
	keyArgs := append([]string{"pkcs12", "-in", inputPath, "-nocerts", "-nodes"}, passArgs...)
	keyArgs = append(keyArgs, "-out", tmpKey)
	if _, _, err := e.runPKCS12(ctx, keyArgs...); err != nil {
		return nil, fmt.Errorf("extract private key: %w", err)
	}
	if err := commitTempFile(tmpKey, result.KeyFile, 0o600); err != nil {
		return nil, err
	}

	// Extract CA certs
	caFile := filepath.Join(outputDir, base+"-ca.crt")
	tmpCA, err := newTempPath(caFile)
	if err != nil {
		return nil, fmt.Errorf("create temp CA file: %w", err)
	}
	defer os.Remove(tmpCA)
	caArgs := append([]string{"pkcs12", "-in", inputPath, "-cacerts", "-nokeys"}, passArgs...)
	caArgs = append(caArgs, "-out", tmpCA)
	e.runPKCS12(ctx, caArgs...) // ignore error, CA certs are optional

	// Check if CA file has content
	if info, err := os.Stat(tmpCA); err == nil && info.Size() > 0 {
		content, err := os.ReadFile(tmpCA)
		if err == nil && strings.Contains(string(content), "BEGIN CERTIFICATE") {
			if err := commitTempFile(tmpCA, caFile, 0o644); err != nil {
				return nil, err
			}
			result.CAFile = caFile
		}
	}

	return result, nil
}

// ToDER converts a PEM file to DER format.
func (e *Engine) ToDER(ctx context.Context, inputPath, outputPath string, isKey bool) error {
	if err := ensureNotExists(outputPath); err != nil {
		return err
	}

	tmp, err := newTempPath(outputPath)
	if err != nil {
		return fmt.Errorf("create temp output: %w", err)
	}
	defer os.Remove(tmp)

	if isKey {
		if err := ValidatePEMKey(inputPath); err != nil {
			return err
		}
		_, stderr, err := e.exec.Run(ctx, "rsa", "-in", inputPath, "-inform", "PEM", "-out", tmp, "-outform", "DER")
		if err != nil {
			return fmt.Errorf("convert key to DER: %w", preferStderr(err, stderr))
		}
		if err := commitTempFile(tmp, outputPath, 0o600); err != nil {
			return err
		}
	} else {
		if err := ValidatePEMCert(inputPath); err != nil {
			return err
		}
		_, stderr, err := e.exec.Run(ctx, "x509", "-in", inputPath, "-inform", "PEM", "-out", tmp, "-outform", "DER")
		if err != nil {
			return fmt.Errorf("convert cert to DER: %w", preferStderr(err, stderr))
		}
		if err := commitTempFile(tmp, outputPath, 0o644); err != nil {
			return err
		}
	}

	// Verify output was created and non-empty
	info, err := os.Stat(outputPath)
	if err != nil || info.Size() == 0 {
		return fmt.Errorf("conversion to DER failed: output file is empty or missing")
	}
	return nil
}

// FromDER converts a DER file to PEM format.
func (e *Engine) FromDER(ctx context.Context, inputPath, outputPath string, isKey bool) error {
	isDER, err := IsDEREncoded(inputPath)
	if err != nil {
		return fmt.Errorf("check DER encoding: %w", err)
	}
	if !isDER {
		return fmt.Errorf("file may not be DER encoded (doesn't start with ASN.1 SEQUENCE tag)")
	}

	if err := ensureNotExists(outputPath); err != nil {
		return err
	}
	tmp, err := newTempPath(outputPath)
	if err != nil {
		return fmt.Errorf("create temp output: %w", err)
	}
	defer os.Remove(tmp)

	if isKey {
		_, stderr, err := e.exec.Run(ctx, "rsa", "-in", inputPath, "-inform", "DER", "-out", tmp, "-outform", "PEM")
		if err != nil {
			return fmt.Errorf(
				"convert DER to key PEM: %w (try without --key if this is a certificate)",
				preferStderr(err, stderr),
			)
		}
		if err := commitTempFile(tmp, outputPath, 0o600); err != nil {
			return err
		}
	} else {
		_, stderr, err := e.exec.Run(ctx, "x509", "-in", inputPath, "-inform", "DER", "-out", tmp, "-outform", "PEM")
		if err != nil {
			return fmt.Errorf(
				"convert DER to cert PEM: %w (try with --key if this is a private key)",
				preferStderr(err, stderr),
			)
		}
		if err := commitTempFile(tmp, outputPath, 0o644); err != nil {
			return err
		}
	}

	info, err := os.Stat(outputPath)
	if err != nil || info.Size() == 0 {
		return fmt.Errorf("conversion from DER failed: output file is empty or missing")
	}
	return nil
}

// ToBase64 encodes a file to raw base64 (no line breaks).
func (e *Engine) ToBase64(_ context.Context, inputPath, outputPath string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	if err := writeFileExclusive(outputPath, []byte(encoded), 0o644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// FromBase64 decodes a base64-encoded file.
func (e *Engine) FromBase64(_ context.Context, inputPath, outputPath string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	content := strings.TrimSpace(string(data))

	if strings.Contains(content, "-----BEGIN") {
		return fmt.Errorf("file appears to be PEM format, not raw Base64 (PEM files are already text - no decoding needed)")
	}

	decoded, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		// Try RawStdEncoding (no padding)
		decoded, err = base64.RawStdEncoding.DecodeString(content)
		if err != nil {
			return fmt.Errorf("base64 decoding failed: file may contain invalid Base64 characters")
		}
	}

	if err := writeFileExclusive(outputPath, decoded, 0o644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// CombinePEM combines a cert, key, and optional CA into a single PEM file.
func (e *Engine) CombinePEM(ctx context.Context, certPath, keyPath, outputPath, caPath string) error {
	if err := ValidatePEMCert(certPath); err != nil {
		return err
	}
	if err := ValidatePEMKey(keyPath); err != nil {
		return err
	}

	m, err := e.MatchKeyToCert(ctx, certPath, keyPath)
	if err != nil {
		return fmt.Errorf("match check: %w", err)
	}
	if !m.Match {
		return fmt.Errorf("private key does NOT match certificate")
	}

	certData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read cert: %w", err)
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}

	var combined []byte
	combined = append(combined, certData...)
	if len(combined) > 0 && combined[len(combined)-1] != '\n' {
		combined = append(combined, '\n')
	}
	combined = append(combined, keyData...)

	if caPath != "" {
		caData, err := os.ReadFile(caPath)
		if err != nil {
			return fmt.Errorf("read CA: %w", err)
		}
		if len(combined) > 0 && combined[len(combined)-1] != '\n' {
			combined = append(combined, '\n')
		}
		combined = append(combined, caData...)
	}

	if err := writeFileExclusive(outputPath, combined, 0o600); err != nil {
		return fmt.Errorf("write combined PEM: %w", err)
	}
	return nil
}
