package cert

import (
	"bufio"
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// KeytoolExecutor runs keytool commands and returns stdout, stderr, and any error.
type KeytoolExecutor interface {
	Run(ctx context.Context, args ...string) (stdout, stderr []byte, err error)
}

// OSKeytoolExecutor calls keytool via exec.CommandContext.
type OSKeytoolExecutor struct{}

func (o *OSKeytoolExecutor) Run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, "keytool", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// SetKeytool attaches a keytool executor to the engine.
func (e *Engine) SetKeytool(kt KeytoolExecutor) {
	e.keytoolExec = kt
}

// HasKeytool returns true if a keytool executor is configured.
func (e *Engine) HasKeytool() bool {
	return e.keytoolExec != nil
}

// JKSAlias describes a single entry in a JKS keystore.
type JKSAlias struct {
	Alias   string `json:"alias"`
	Type    string `json:"type"`
	Subject string `json:"subject,omitempty"`
}

// JKSSummary holds the parsed keystore listing.
type JKSSummary struct {
	File    string     `json:"file"`
	Aliases []JKSAlias `json:"aliases"`
}

// FromJKSResult holds the output paths from a JKS extraction.
type FromJKSResult struct {
	CertFiles []string `json:"cert_files"`
}

var (
	aliasRE = regexp.MustCompile(`^Alias name:\s*(.+)$`)
	entryRE = regexp.MustCompile(`^Entry type:\s*(.+)$`)
	ownerRE = regexp.MustCompile(`^Owner:\s*(.+)$`)
)

// JKSList lists all aliases in a JKS keystore.
func (e *Engine) JKSList(ctx context.Context, path, password string) (*JKSSummary, error) {
	if e.keytoolExec == nil {
		return nil, fmt.Errorf("keytool not found — install a JDK to enable JKS support")
	}

	// Write password to temp file for -storepass:file.
	pwFile, err := writeTempPassword(password)
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(pwFile) }()

	stdout, stderr, err := e.keytoolExec.Run(ctx,
		"-list", "-v", "-keystore", path, "-storepass:file", pwFile)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("keytool list: %s", msg)
	}

	summary := &JKSSummary{File: path}
	summary.Aliases = parseKeytoolListOutput(stdout)
	return summary, nil
}

func parseKeytoolListOutput(data []byte) []JKSAlias {
	var aliases []JKSAlias
	var current *JKSAlias

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()

		if m := aliasRE.FindStringSubmatch(line); m != nil {
			if current != nil {
				aliases = append(aliases, *current)
			}
			current = &JKSAlias{Alias: strings.TrimSpace(m[1])}
			continue
		}
		if current == nil {
			continue
		}
		if m := entryRE.FindStringSubmatch(line); m != nil {
			current.Type = strings.TrimSpace(m[1])
		}
		if m := ownerRE.FindStringSubmatch(line); m != nil {
			current.Subject = strings.TrimSpace(m[1])
		}
	}
	if current != nil {
		aliases = append(aliases, *current)
	}
	return aliases
}

// FromJKS exports certificates from a JKS keystore to PEM files.
// If alias is empty, all trusted certificate entries are exported.
func (e *Engine) FromJKS(ctx context.Context, path, outDir, password, alias string) (*FromJKSResult, error) {
	if e.keytoolExec == nil {
		return nil, fmt.Errorf("keytool not found — install a JDK to enable JKS support")
	}

	// List aliases to know what to export.
	summary, err := e.JKSList(ctx, path, password)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	pwFile, err := writeTempPassword(password)
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(pwFile) }()

	result := &FromJKSResult{}
	for _, a := range summary.Aliases {
		if alias != "" && a.Alias != alias {
			continue
		}

		// Export DER cert.
		tmpDER, err := os.CreateTemp("", "certconv-jks-*.der")
		if err != nil {
			return nil, err
		}
		tmpDERPath := tmpDER.Name()
		_ = tmpDER.Close()
		defer func() { _ = os.Remove(tmpDERPath) }()

		_, stderr, err := e.keytoolExec.Run(ctx,
			"-exportcert",
			"-keystore", path,
			"-alias", a.Alias,
			"-storepass:file", pwFile,
			"-file", tmpDERPath)
		if err != nil {
			msg := strings.TrimSpace(string(stderr))
			if msg == "" {
				msg = err.Error()
			}
			return nil, fmt.Errorf("export alias %q: %s", a.Alias, msg)
		}

		// Convert DER to PEM.
		derData, err := os.ReadFile(tmpDERPath)
		if err != nil {
			return nil, err
		}

		var pemBuf bytes.Buffer
		if err := pem.Encode(&pemBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derData}); err != nil {
			return nil, fmt.Errorf("encode PEM for alias %q: %w", a.Alias, err)
		}

		safeName := strings.Map(func(r rune) rune {
			if r == '/' || r == '\\' || r == ':' || r == ' ' {
				return '_'
			}
			return r
		}, a.Alias)
		dest := filepath.Join(outDir, safeName+".pem")
		dest = NextAvailablePath(dest)

		if err := writeFileExclusive(dest, pemBuf.Bytes(), 0o644); err != nil {
			return nil, fmt.Errorf("write alias %q: %w", a.Alias, err)
		}
		result.CertFiles = append(result.CertFiles, dest)
	}

	if len(result.CertFiles) == 0 {
		if alias != "" {
			return nil, fmt.Errorf("alias %q not found in keystore", alias)
		}
		return nil, fmt.Errorf("no certificate entries found in keystore")
	}

	return result, nil
}

func writeTempPassword(password string) (string, error) {
	f, err := os.CreateTemp("", "certconv-pw-*")
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(password); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	_ = os.Chmod(f.Name(), 0o600)
	return f.Name(), nil
}
