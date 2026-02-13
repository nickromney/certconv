package cert

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Summary returns a CertSummary for the given file.
func (e *Engine) Summary(ctx context.Context, path string, password string) (*CertSummary, error) {
	ft, err := DetectType(path)
	if err != nil {
		return nil, fmt.Errorf("detect type: %w", err)
	}

	s := &CertSummary{
		File:     path,
		FileType: ft,
	}

	switch ft {
	case FileTypePFX:
		// Extract cert from PFX then parse
		extra := []ExtraFile{{Data: []byte(password)}}
		pemOut, stderr, err := e.runPKCS12WithExtraFiles(ctx, extra,
			"pkcs12", "-in", path, "-nokeys",
			"-passin", fdArg(0),
		)
		if err != nil {
			return s, fmt.Errorf("read pfx: %w", pfxReadError(err, stderr))
		}
		s, err = e.parseCertSummaryFromPEM(ctx, s, pemOut)
		if err == nil {
			if c, perr := ParseCertBytes(pemOut); perr == nil {
				EnrichSummary(s, c)
			}
		}
		return s, err

	case FileTypeDER:
		stdout, _, err := e.exec.Run(ctx, "x509", "-in", path, "-inform", "DER",
			"-noout", "-subject", "-issuer", "-dates", "-serial")
		if err != nil {
			return s, fmt.Errorf("read der cert: %w", err)
		}
		parseSummaryFields(s, stdout)
		if c, perr := ParseCertFile(path); perr == nil {
			EnrichSummary(s, c)
		}
		return s, nil

	case FileTypeCert, FileTypeCombined:
		stdout, _, err := e.exec.Run(ctx, "x509", "-in", path,
			"-noout", "-subject", "-issuer", "-dates", "-serial")
		if err != nil {
			return s, fmt.Errorf("read pem cert: %w", err)
		}
		parseSummaryFields(s, stdout)
		if c, perr := ParseCertFile(path); perr == nil {
			EnrichSummary(s, c)
		}
		return s, nil

	case FileTypeKey:
		s.KeyType = detectKeyType(path)
		return s, nil

	case FileTypePublicKey:
		// Best-effort: OpenSSH "ssh-..." public keys are common.
		line, err := ReadFirstNonEmptyLine(path)
		if err == nil {
			if pk, pkErr := ParseOpenSSHPublicKeyLine(line); pkErr == nil && pk != nil {
				s.PublicKeyAlgorithm = pk.Algorithm
				s.PublicKeyComment = pk.Comment
			} else if hasPublicKeyMarker(path) {
				s.PublicKeyAlgorithm = "PEM"
			}
		}
		return s, nil

	default:
		return s, nil
	}
}

// parseCertSummaryFromPEM pipes PEM bytes through x509 to extract summary fields.
func (e *Engine) parseCertSummaryFromPEM(ctx context.Context, s *CertSummary, pemData []byte) (*CertSummary, error) {
	// Write PEM to a temp file for openssl
	tmp, err := os.CreateTemp("", "certconv-*.pem")
	if err != nil {
		return s, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(pemData); err != nil {
		tmp.Close()
		return s, err
	}
	tmp.Close()

	stdout, _, err := e.exec.Run(ctx, "x509", "-in", tmp.Name(),
		"-noout", "-subject", "-issuer", "-dates", "-serial")
	if err != nil {
		return s, err
	}
	parseSummaryFields(s, stdout)
	return s, nil
}

// PFXCertsPEM extracts all certificates from a PFX (including chain when present)
// as PEM bytes. The password may be empty.
func (e *Engine) PFXCertsPEM(ctx context.Context, path string, password string) ([]byte, error) {
	extra := []ExtraFile{{Data: []byte(password)}}
	stdout, stderr, err := e.runPKCS12WithExtraFiles(ctx, extra,
		"pkcs12", "-in", path, "-nokeys",
		"-passin", fdArg(0),
	)
	if err != nil {
		return nil, fmt.Errorf("read pfx certificates: %w", pfxReadError(err, stderr))
	}
	return stdout, nil
}

// parseSummaryFields parses openssl x509 output lines into CertSummary fields.
func parseSummaryFields(s *CertSummary, data []byte) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "subject="):
			s.Subject = strings.TrimSpace(strings.TrimPrefix(line, "subject="))
		case strings.HasPrefix(line, "issuer="):
			s.Issuer = strings.TrimSpace(strings.TrimPrefix(line, "issuer="))
		case strings.HasPrefix(line, "notBefore="):
			s.NotBefore = strings.TrimSpace(strings.TrimPrefix(line, "notBefore="))
		case strings.HasPrefix(line, "notAfter="):
			s.NotAfter = strings.TrimSpace(strings.TrimPrefix(line, "notAfter="))
		case strings.HasPrefix(line, "serial="):
			s.Serial = strings.TrimSpace(strings.TrimPrefix(line, "serial="))
		}
	}
}

// detectKeyType determines key type by scanning PEM headers.
func detectKeyType(path string) KeyType {
	f, err := os.Open(path)
	if err != nil {
		return KeyTypePKCS8
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "RSA PRIVATE KEY") {
			return KeyTypeRSA
		}
		if strings.Contains(line, "EC PRIVATE KEY") {
			return KeyTypeEC
		}
	}
	return KeyTypePKCS8
}

// Details returns the full text output of the certificate.
func (e *Engine) Details(ctx context.Context, path string, password string) (*CertDetails, error) {
	ft, err := DetectType(path)
	if err != nil {
		return nil, fmt.Errorf("detect type: %w", err)
	}

	d := &CertDetails{
		File:     path,
		FileType: ft,
	}

	var stdout []byte

	switch ft {
	case FileTypePFX:
		extra := []ExtraFile{{Data: []byte(password)}}
		pemOut, stderr, err := e.runPKCS12WithExtraFiles(ctx, extra,
			"pkcs12", "-in", path, "-nokeys",
			"-passin", fdArg(0),
		)
		if err != nil {
			return d, fmt.Errorf("read pfx: %w", pfxReadError(err, stderr))
		}
		tmp, err := os.CreateTemp("", "certconv-*.pem")
		if err != nil {
			return d, err
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.Write(pemOut); err != nil {
			tmp.Close()
			return d, err
		}
		tmp.Close()
		stdout, _, err = e.exec.Run(ctx, "x509", "-in", tmp.Name(), "-text", "-noout")
		if err != nil {
			return d, err
		}

	case FileTypeDER:
		stdout, _, err = e.exec.Run(ctx, "x509", "-in", path, "-inform", "DER", "-text", "-noout")
		if err != nil {
			return d, err
		}

	case FileTypeCert, FileTypeCombined:
		stdout, _, err = e.exec.Run(ctx, "x509", "-in", path, "-text", "-noout")
		if err != nil {
			return d, err
		}

	case FileTypePublicKey:
		// Prefer OpenSSH formatting (common: ssh-ed25519 ...).
		line, lerr := ReadFirstNonEmptyLine(path)
		if lerr == nil {
			if pk, pkErr := ParseOpenSSHPublicKeyLine(line); pkErr == nil && pk != nil {
				fp, sz, fpErr := openSSHSHA256FingerprintFromBase64(pk.Base64)
				if fpErr != nil {
					fp = "SHA256:<unavailable>"
				}

				var b strings.Builder
				b.WriteString("Public key (OpenSSH)\n\n")
				b.WriteString("Algorithm: " + pk.Algorithm + "\n")
				if strings.TrimSpace(pk.Comment) != "" {
					b.WriteString("Comment: " + pk.Comment + "\n")
				}
				if fpErr == nil {
					b.WriteString("Size: " + strconv.Itoa(sz) + " bytes\n")
				}
				b.WriteString("Fingerprint: " + fp + "\n\n")
				b.WriteString("Line:\n" + pk.RawLine + "\n")
				d.RawText = b.String()
				return d, nil
			}
		}

		// PEM public key: try to render using openssl.
		if hasPublicKeyMarker(path) {
			stdout, _, err = e.exec.Run(ctx, "pkey", "-pubin", "-in", path, "-text", "-noout")
			if err != nil {
				return d, err
			}
			d.RawText = string(stdout)
			return d, nil
		}

		return d, fmt.Errorf("unrecognised public key format")

	default:
		return d, fmt.Errorf("cannot show full details for file type: %s", ft)
	}

	d.RawText = string(stdout)
	return d, nil
}

// Expiry checks whether a certificate expires within the given number of days.
func (e *Engine) Expiry(ctx context.Context, path string, days int) (*ExpiryResult, error) {
	ft, err := DetectType(path)
	if err != nil {
		return nil, fmt.Errorf("detect type: %w", err)
	}

	result := &ExpiryResult{}

	// Get the expiry date
	var args []string
	switch ft {
	case FileTypeDER:
		args = []string{"x509", "-in", path, "-inform", "DER", "-noout", "-enddate"}
	default:
		args = []string{"x509", "-in", path, "-noout", "-enddate"}
	}

	stdout, _, err := e.exec.Run(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("read certificate expiry: %w", err)
	}

	// Parse "notAfter=Mon DD HH:MM:SS YYYY GMT"
	line := strings.TrimSpace(string(stdout))
	parts := strings.SplitN(line, "=", 2)
	if len(parts) == 2 {
		result.ExpiryDate = strings.TrimSpace(parts[1])
	}

	// Parse the date
	if result.ExpiryDate != "" {
		t, err := time.Parse("Jan  2 15:04:05 2006 GMT", result.ExpiryDate)
		if err != nil {
			// Try alternate format with single-digit day
			t, err = time.Parse("Jan 2 15:04:05 2006 GMT", result.ExpiryDate)
		}
		if err == nil {
			result.ExpiresAt = t
			result.DaysLeft = int(time.Until(t).Hours() / 24)
		}
	}

	// Check if valid for N days
	checkSeconds := strconv.Itoa(days * 86400)
	switch ft {
	case FileTypeDER:
		args = []string{"x509", "-in", path, "-inform", "DER", "-checkend", checkSeconds, "-noout"}
	default:
		args = []string{"x509", "-in", path, "-checkend", checkSeconds, "-noout"}
	}

	_, _, checkErr := e.exec.Run(ctx, args...)
	result.Valid = checkErr == nil

	return result, nil
}
