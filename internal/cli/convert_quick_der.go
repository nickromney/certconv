package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nickromney/certconv/internal/cert"
)

func quickDERBytes(ctx context.Context, engine *cert.Engine, inputPath, password, keyPassword string) ([]byte, error) {
	ft, err := cert.DetectType(inputPath)
	if err != nil {
		return nil, fmt.Errorf("detect type: %w", err)
	}

	readNonEmpty := func(path string) ([]byte, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if len(b) == 0 {
			return nil, fmt.Errorf("conversion to DER produced empty output")
		}
		return b, nil
	}
	withTempOut := func(name string, fn func(outputPath string) error) ([]byte, error) {
		tmpDir, err := os.MkdirTemp("", "certconv-quick-der-*")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmpDir)
		outPath := filepath.Join(tmpDir, name)
		if err := fn(outPath); err != nil {
			return nil, err
		}
		return readNonEmpty(outPath)
	}

	switch ft {
	case cert.FileTypeCert, cert.FileTypeCombined:
		return engine.CertDER(ctx, inputPath)
	case cert.FileTypeDER:
		return readNonEmpty(inputPath)
	case cert.FileTypePFX:
		pemOut, err := engine.PFXCertsPEM(ctx, inputPath, password)
		if err != nil {
			return nil, err
		}
		tmpDir, err := os.MkdirTemp("", "certconv-quick-pfx-*")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmpDir)
		pemPath := filepath.Join(tmpDir, "from-pfx.pem")
		if err := os.WriteFile(pemPath, pemOut, 0o600); err != nil {
			return nil, err
		}
		return engine.CertDER(ctx, pemPath)
	case cert.FileTypeBase64:
		return withTempOut("decoded.der", func(outputPath string) error {
			return engine.FromBase64(ctx, inputPath, outputPath)
		})
	case cert.FileTypeKey:
		return withTempOut("key.der", func(outputPath string) error {
			return engine.ToDER(ctx, inputPath, outputPath, true, keyPassword)
		})
	default:
		isDER, derr := cert.IsDEREncoded(inputPath)
		if derr == nil && isDER {
			return readNonEmpty(inputPath)
		}
		return nil, fmt.Errorf("quick DER conversion not supported for detected type %q (use explicit subcommands)", ft)
	}
}
