package cert

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FromP7BResult holds the output paths from a P7B extraction.
type FromP7BResult struct {
	CertFiles []string `json:"cert_files"`
}

// P7BSummary extracts the first certificate from a P7B file and returns
// a CertSummary for it.
func (e *Engine) P7BSummary(ctx context.Context, path string) (*CertSummary, error) {
	stdout, stderr, err := e.exec.Run(ctx, "pkcs7", "-print_certs", "-in", path)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("read p7b: %s", msg)
	}

	s := &CertSummary{
		File:     path,
		FileType: FileTypeP7B,
	}

	s, err = e.parseCertSummaryFromPEM(ctx, s, stdout)
	if err != nil {
		return s, err
	}
	if c, perr := ParseCertBytes(stdout); perr == nil {
		EnrichSummary(s, c)
	}
	return s, nil
}

// P7BDetails returns the full text details of the first certificate in a P7B.
func (e *Engine) P7BDetails(ctx context.Context, path string) (*CertDetails, error) {
	stdout, stderr, err := e.exec.Run(ctx, "pkcs7", "-print_certs", "-in", path)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("read p7b: %s", msg)
	}

	// Write extracted PEM to temp file for x509 -text.
	tmp, err := os.CreateTemp("", "certconv-p7b-*.pem")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(stdout); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	_ = tmp.Close()

	textOut, _, err := e.exec.Run(ctx, "x509", "-in", tmp.Name(), "-text", "-noout")
	if err != nil {
		return nil, err
	}

	return &CertDetails{
		File:     path,
		FileType: FileTypeP7B,
		RawText:  string(textOut),
	}, nil
}

// FromP7B extracts all certificates from a P7B file to individual PEM files.
func (e *Engine) FromP7B(ctx context.Context, path, outDir string) (*FromP7BResult, error) {
	stdout, stderr, err := e.exec.Run(ctx, "pkcs7", "-print_certs", "-in", path)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("read p7b: %s", msg)
	}

	// Split PEM output into individual certificate blocks.
	var blocks []*pem.Block
	rest := stdout
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = r
		if block.Type == "CERTIFICATE" {
			blocks = append(blocks, block)
		}
	}

	if len(blocks) == 0 {
		return nil, fmt.Errorf("no certificates found in P7B file")
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	result := &FromP7BResult{}

	for i, block := range blocks {
		var buf bytes.Buffer
		if err := pem.Encode(&buf, block); err != nil {
			return nil, fmt.Errorf("encode cert %d: %w", i, err)
		}

		name := fmt.Sprintf("%s-%d.pem", base, i)
		dest := filepath.Join(outDir, name)
		dest = NextAvailablePath(dest)

		if err := writeFileExclusive(dest, buf.Bytes(), 0o644); err != nil {
			return nil, fmt.Errorf("write cert %d: %w", i, err)
		}
		result.CertFiles = append(result.CertFiles, dest)
	}

	return result, nil
}
