package cert

import (
	"context"
	"fmt"
	"os"
)

// CertDER returns the DER bytes for a PEM certificate (or combined PEM containing a cert).
// This is a preview-only helper: it does not write any output files.
func (e *Engine) CertDER(ctx context.Context, pemCertPath string) ([]byte, error) {
	if err := ValidatePEMCert(pemCertPath); err != nil {
		// Combined PEM (.key with cert) is still acceptable as long as it has a cert marker.
		return nil, err
	}
	stdout, stderr, err := e.exec.Run(ctx, "x509", "-in", pemCertPath, "-outform", "DER")
	if err != nil {
		msg := string(stderr)
		if msg != "" {
			return nil, fmt.Errorf("convert to DER: %s", msg)
		}
		return nil, fmt.Errorf("convert to DER: %w", err)
	}
	if len(stdout) == 0 {
		return nil, fmt.Errorf("convert to DER: no output")
	}
	return stdout, nil
}

// PFXBytes returns the PKCS#12/PFX bytes for a PEM cert + key.
// This is a preview-only helper: it does not write any output files.
func (e *Engine) PFXBytes(ctx context.Context, certPath, keyPath, password, caPath string) ([]byte, error) {
	if err := ValidatePEMCert(certPath); err != nil {
		return nil, err
	}
	if err := ValidatePEMKey(keyPath); err != nil {
		return nil, err
	}

	// Check key matches cert.
	m, err := e.MatchKeyToCert(ctx, certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("match check: %w", err)
	}
	if m == nil || !m.Match {
		return nil, fmt.Errorf("private key does NOT match certificate")
	}

	tmp, err := os.CreateTemp("", "certconv-preview-*.pfx")
	if err != nil {
		return nil, fmt.Errorf("create temp PFX: %w", err)
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	args := []string{"pkcs12", "-export", "-out", tmpPath, "-inkey", keyPath, "-in", certPath}
	if caPath != "" {
		args = append(args, "-certfile", caPath)
	}
	args = append(args, "-passout", "pass:"+password)

	_, stderr, err := e.runPKCS12(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("create PFX: %w", pfxReadError(err, stderr))
	}

	b, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("read temp PFX: %w", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("create PFX: no output")
	}
	return b, nil
}
