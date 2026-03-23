package tui

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nickromney/certconv/internal/cert"
)

// loadFileContent reads a file and returns a FileContentMsg.
func (m Model) loadFileContent(path string) tea.Cmd {
	return func() tea.Msg {
		data, err := os.ReadFile(path)
		if err != nil {
			return FileContentMsg{Path: path, Err: err}
		}

		content := string(data)
		// Truncate very large files
		const maxDisplay = 10000
		if len(content) > maxDisplay {
			content = content[:maxDisplay] + fmt.Sprintf("\n\n... (truncated, %d bytes total)", len(data))
		}

		// Check if binary
		isBinary := false
		for _, b := range data[:min(512, len(data))] {
			if b == 0 {
				isBinary = true
				break
			}
		}
		if isBinary {
			content = fmt.Sprintf("[Binary file, %d bytes]", len(data))
		}

		return FileContentMsg{Path: path, Content: content}
	}
}

// loadCertSummary runs Engine.Summary and returns a CertSummaryMsg.
func (m Model) loadCertSummary(path string) tea.Cmd {
	return func() tea.Msg {
		pw := m.pfxPassword(path)
		s, err := m.engine.Summary(m.ctx(), path, pw)
		return CertSummaryMsg{Path: path, Summary: s, Err: err}
	}
}

func (m Model) loadContentDetails(path string) tea.Cmd {
	return func() tea.Msg {
		pw := m.pfxPassword(path)
		d, err := m.engine.Details(m.ctx(), path, pw)
		if err != nil || d == nil {
			return ContentDetailsMsg{Path: path, Details: d, Err: err}
		}

		var prefixParts []string

		// Chain summary from the file (PEM/DER) or extracted from PFX.
		if chain, ok := chainSummaryForFile(path); ok {
			prefixParts = append(prefixParts, chain)
		} else if d.FileType == cert.FileTypePFX {
			pemOut, pemErr := m.engine.PFXCertsPEM(m.ctx(), path, pw)
			if pemErr == nil {
				if chain, ok := chainSummaryFromBytes(pemOut); ok {
					prefixParts = append(prefixParts, chain)
				}
			}
		}

		if d.FileType == cert.FileTypePFX {
			if pw == "" {
				prefixParts = append(prefixParts,
					"PFX password: empty (pass:). This is not a meaningful security boundary.",
				)
			} else {
				if m.pfxEmptyRejected != nil && m.pfxEmptyRejected[path] {
					prefixParts = append(prefixParts, "PFX password: non-empty (user-provided; empty password rejected).")
				} else {
					prefixParts = append(prefixParts, "PFX password: non-empty (user-provided).")
				}
			}
		}

		if len(prefixParts) > 0 {
			d.RawText = strings.Join(prefixParts, "\n\n") + "\n\n" + d.RawText
		}

		return ContentDetailsMsg{Path: path, Details: d}
	}
}

func (m Model) loadDerivedDERBase64(path string) tea.Cmd {
	return func() tea.Msg {
		der, err := m.engine.CertDER(m.ctx(), path)
		if err != nil {
			return ContentDERBase64Msg{Path: path, Err: err}
		}
		enc := base64.StdEncoding.EncodeToString(der)
		return ContentDERBase64Msg{Path: path, Text: enc}
	}
}

func (m Model) loadDerivedPFXBase64(certPath, keyPath string) tea.Cmd {
	return func() tea.Msg {
		pfx, err := m.engine.PFXBytes(m.ctx(), certPath, keyPath, "", "")
		if err != nil {
			return ContentPFXBase64Msg{Path: certPath, Err: err}
		}
		enc := base64.StdEncoding.EncodeToString(pfx)
		return ContentPFXBase64Msg{Path: certPath, Text: enc}
	}
}

func (m Model) loadContentParsed(path string) tea.Cmd {
	return func() tea.Msg {
		text, err := renderParsedCert(path, m.pfxPassword(path), m.engine, m.ctx())
		if err != nil {
			return ContentParsedMsg{Path: path, Err: err}
		}
		return ContentParsedMsg{Path: path, Text: text}
	}
}

func (m Model) loadContentModulus(path string) tea.Cmd {
	return func() tea.Msg {
		mod, err := m.engine.RSAModulus(m.ctx(), path)
		if err != nil {
			if errors.Is(err, cert.ErrNotRSA) {
				return ContentModulusMsg{Path: path, Err: fmt.Errorf("modulus is RSA-only (not an RSA key/certificate)")}
			}
			return ContentModulusMsg{Path: path, Err: err}
		}

		sha, md := cert.ModulusDigestsHex(mod)

		var b strings.Builder

		labelW := 18
		kv := func(k, v string) {
			if v == "" {
				return
			}
			fmt.Fprintf(&b, "%-*s %s\n", labelW, k+":", v)
		}

		b.WriteString("Modulus (hex):\n")
		b.WriteString(wrapFixed(mod, m.contentPane.oneLineWrapWidth))
		b.WriteString("\n\n")
		kv("SHA256(modulus)", sha)
		kv("MD5(modulus)", md)

		// If we auto-matched a key for a cert, show the comparison (RSA only).
		if (m.selectedType == cert.FileTypeCert || m.selectedType == cert.FileTypeCombined || m.selectedType == cert.FileTypeDER) &&
			strings.TrimSpace(m.autoMatchedKeyPath) != "" {
			keyMod, kerr := m.engine.RSAModulus(m.ctx(), m.autoMatchedKeyPath)
			if kerr == nil {
				ksha, kmd := cert.ModulusDigestsHex(keyMod)
				match := "NO"
				if strings.TrimSpace(mod) == strings.TrimSpace(keyMod) {
					match = "YES"
				}
				b.WriteString("\n")
				kv("Auto-matched key", filepath.Base(m.autoMatchedKeyPath))
				kv("Key SHA256(modulus)", ksha)
				kv("Key MD5(modulus)", kmd)
				kv("Match", match)
			} else if errors.Is(kerr, cert.ErrNotRSA) {
				b.WriteString("\n")
				kv("Auto-matched key", filepath.Base(m.autoMatchedKeyPath)+" (not RSA; no modulus)")
			}
		}

		return ContentModulusMsg{Path: path, Text: b.String()}
	}
}

func (m Model) loadContentOneLine(path string) tea.Cmd {
	return func() tea.Msg {
		data, err := os.ReadFile(path)
		if err != nil {
			return ContentOneLineMsg{Path: path, Err: err}
		}

		const maxBytes = 256 * 1024
		if len(data) > maxBytes {
			return ContentOneLineMsg{Path: path, Err: fmt.Errorf("file too large for one-line view (%d bytes)", len(data))}
		}

		// If binary, don't try to render; guide the user to Base64 view.
		for _, b := range data[:min(512, len(data))] {
			if b == 0 {
				return ContentOneLineMsg{Path: path, Err: fmt.Errorf("binary file; use base64 view")}
			}
		}

		s := string(data)
		alreadySingleLine := !strings.Contains(s, "\n") && !strings.Contains(s, "\r")
		s = strings.ReplaceAll(s, "\r", "")
		s = strings.ReplaceAll(s, "\n", "")
		return ContentOneLineMsg{Path: path, Text: s, AlreadySingleLine: alreadySingleLine}
	}
}

func (m Model) loadContentBase64(path string) tea.Cmd {
	return func() tea.Msg {
		data, err := os.ReadFile(path)
		if err != nil {
			return ContentBase64Msg{Path: path, Err: err}
		}

		const maxBytes = 2 * 1024 * 1024
		if len(data) > maxBytes {
			return ContentBase64Msg{Path: path, Err: fmt.Errorf("file too large for base64 view (%d bytes)", len(data))}
		}

		// Single-line output to match common Azure KeyVault workflows.
		enc := base64.StdEncoding.EncodeToString(data)
		return ContentBase64Msg{Path: path, Text: enc}
	}
}
