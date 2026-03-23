package webapi

import (
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/nickromney/certconv/internal/cert"
)

type Action struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

type Analysis struct {
	FileName         string            `json:"fileName"`
	FileType         cert.FileType     `json:"fileType"`
	Summary          *cert.CertSummary `json:"summary,omitempty"`
	Lint             *cert.LintResult  `json:"lint,omitempty"`
	CertCount        int               `json:"certCount,omitempty"`
	PasswordRequired bool              `json:"passwordRequired,omitempty"`
	Notes            []string          `json:"notes,omitempty"`
	Actions          []Action          `json:"actions"`
}

type Output struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	MIME   string `json:"mime"`
	Text   string `json:"text,omitempty"`
	Base64 string `json:"base64,omitempty"`
}

type Request struct {
	Op          string `json:"op"`
	Name        string `json:"name,omitempty"`
	Password    string `json:"password,omitempty"`
	InputBase64 string `json:"inputBase64,omitempty"`
}

type Response struct {
	OK       bool      `json:"ok"`
	Error    string    `json:"error,omitempty"`
	Analysis *Analysis `json:"analysis,omitempty"`
	Output   *Output   `json:"output,omitempty"`
}

func AnalyzeFile(name string, data []byte, password string) *Analysis {
	ft := cert.DetectTypeFromNameAndBytes(name, data)
	analysis := &Analysis{
		FileName: name,
		FileType: ft,
		Actions:  make([]Action, 0, 4),
	}

	switch ft {
	case cert.FileTypeCert, cert.FileTypeCombined, cert.FileTypeDER:
		if summary, err := cert.SummaryFromBytesWithPassword(name, data, password); err == nil {
			analysis.Summary = summary
		} else {
			analysis.Notes = append(analysis.Notes, "Could not parse certificate summary: "+err.Error())
		}
		if lint, err := cert.LintBytesWithPassword(name, data, password); err == nil {
			analysis.Lint = lint
		}
	case cert.FileTypeKey, cert.FileTypePublicKey:
		if summary, err := cert.SummaryFromBytesWithPassword(name, data, password); err == nil {
			analysis.Summary = summary
		}
	case cert.FileTypePFX:
		if summary, err := cert.SummaryFromBytesWithPassword(name, data, password); err == nil {
			analysis.Summary = summary
			if lint, lintErr := cert.LintBytesWithPassword(name, data, password); lintErr == nil {
				analysis.Lint = lint
			}
			if _, certs, parseErr := cert.ParsePFXCertificates(data, password); parseErr == nil {
				analysis.CertCount = len(certs)
				if len(certs) > 1 {
					analysis.Notes = append(analysis.Notes, fmt.Sprintf("Detected %d certificates inside this PFX/P12 container.", len(certs)))
				}
			}
		} else {
			switch {
			case errors.Is(err, cert.ErrPFXIncorrectPassword):
				analysis.PasswordRequired = true
				if password == "" {
					analysis.Notes = append(analysis.Notes, "This PFX/P12 is password-protected. Enter the container password to inspect the certificate inside it.")
				} else {
					analysis.Notes = append(analysis.Notes, "The supplied PFX/P12 password did not unlock this container. Check the password and try again.")
				}
			case errors.Is(err, cert.ErrPFXUnsupportedStructure):
				analysis.Notes = append(analysis.Notes, "This PFX/P12 is valid, but its structure is not yet supported by the browser build.")
			case errors.Is(err, cert.ErrPFXNotPKCS12):
				analysis.Notes = append(analysis.Notes, "This file does not decode as a valid PKCS#12/PFX container.")
			default:
				analysis.Notes = append(analysis.Notes, "Could not parse PFX/P12 contents: "+err.Error())
			}
		}
	case cert.FileTypeP7B:
		analysis.Notes = append(analysis.Notes, "PKCS#7/P7B support is not yet available in the browser build because the CLI currently routes it through openssl.")
	case cert.FileTypeBase64:
		analysis.Notes = append(analysis.Notes, "This looks like raw base64. Decode it in-browser, then analyze the resulting file if needed.")
	case cert.FileTypeUnknown:
		analysis.Notes = append(analysis.Notes, "The browser build could not confidently classify this file.")
	}

	if count := cert.CountPEMCertificates(data); count > 0 {
		analysis.CertCount = count
		if count > 1 {
			analysis.Notes = append(analysis.Notes, fmt.Sprintf("Detected %d PEM certificates in this input.", count))
		}
	}

	analysis.Actions = append(analysis.Actions, baseActions(ft, analysis.CertCount)...)
	return analysis
}

func Invoke(req Request) Response {
	data, err := decodeRequestBytes(req.InputBase64)
	if err != nil {
		return Response{OK: false, Error: err.Error()}
	}

	switch req.Op {
	case "analyze":
		return Response{OK: true, Analysis: AnalyzeFile(req.Name, data, req.Password)}

	case "order-chain":
		result, orderedPEM, err := cert.OrderChainFromPEM(data)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		notes := []string{}
		if len(result.Warnings) > 0 {
			notes = append(notes, result.Warnings...)
		}
		return Response{
			OK: true,
			Output: &Output{
				Kind: "text",
				Name: orderedPEMName(req.Name),
				MIME: "text/plain;charset=utf-8",
				Text: string(orderedPEM),
			},
			Analysis: &Analysis{
				FileName: req.Name,
				FileType: cert.DetectTypeFromNameAndBytes(req.Name, data),
				Notes:    notes,
			},
		}

	case "convert-to-der":
		out, err := cert.CertToDERBytes(data)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{
			OK: true,
			Output: &Output{
				Kind:   "binary",
				Name:   replaceExt(req.Name, ".der", "certificate.der"),
				MIME:   "application/octet-stream",
				Base64: base64.StdEncoding.EncodeToString(out),
			},
		}

	case "convert-from-der":
		out, err := cert.CertFromDERBytes(data)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{
			OK: true,
			Output: &Output{
				Kind: "text",
				Name: replaceExt(req.Name, ".pem", "certificate.pem"),
				MIME: "text/plain;charset=utf-8",
				Text: string(out),
			},
		}

	case "encode-base64":
		out := cert.ToBase64Bytes(data)
		return Response{
			OK: true,
			Output: &Output{
				Kind: "text",
				Name: req.Name + ".b64",
				MIME: "text/plain;charset=utf-8",
				Text: string(out),
			},
		}

	case "decode-base64":
		out, err := cert.FromBase64Bytes(data)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{
			OK: true,
			Output: &Output{
				Kind:   "binary",
				Name:   decodedName(req.Name),
				MIME:   "application/octet-stream",
				Base64: base64.StdEncoding.EncodeToString(out),
			},
		}

	case "extract-pfx":
		out, err := cert.ExtractPFXToPEM(data, req.Password)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{
			OK: true,
			Output: &Output{
				Kind: "text",
				Name: replaceExt(req.Name, ".pem", "extracted.pem"),
				MIME: "text/plain;charset=utf-8",
				Text: string(out),
			},
		}

	case "check-expiry":
		text, err := cert.CheckExpiry(req.Name, data, req.Password)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{
			OK: true,
			Output: &Output{
				Kind: "text",
				Name: "expiry-check.txt",
				MIME: "text/plain;charset=utf-8",
				Text: text,
			},
		}
	}

	return Response{OK: false, Error: "unknown operation: " + req.Op}
}

func baseActions(ft cert.FileType, certCount int) []Action {
	actions := []Action{}

	switch ft {
	case cert.FileTypeCert, cert.FileTypeCombined:
		actions = append(actions, Action{
			ID:          "check-expiry",
			Label:       "Check Expiry",
			Description: "Check whether the certificate is expired or expiring soon.",
		})
		actions = append(actions, Action{
			ID:          "convert-to-der",
			Label:       "Export DER",
			Description: "Convert the first certificate block to raw DER bytes.",
		})
		if certCount > 1 {
			actions = append(actions, Action{
				ID:          "order-chain",
				Label:       "Order Bundle",
				Description: "Reorder PEM certificates from leaf to root.",
			})
		}
	case cert.FileTypeDER:
		actions = append(actions, Action{
			ID:          "check-expiry",
			Label:       "Check Expiry",
			Description: "Check whether the certificate is expired or expiring soon.",
		})
		actions = append(actions, Action{
			ID:          "convert-from-der",
			Label:       "Export PEM",
			Description: "Wrap the DER certificate in a PEM block.",
		})
	case cert.FileTypePFX:
		actions = append(actions, Action{
			ID:          "extract-pfx",
			Label:       "Extract PFX",
			Description: "Extract the certificate, private key, and CA chain as PEM.",
		})
		actions = append(actions, Action{
			ID:          "check-expiry",
			Label:       "Check Expiry",
			Description: "Check whether the certificate is expired or expiring soon.",
		})
	case cert.FileTypeBase64:
		actions = append(actions, Action{
			ID:          "decode-base64",
			Label:       "Decode Base64",
			Description: "Decode the raw base64 payload back to bytes.",
		})
	}

	if ft != cert.FileTypeBase64 {
		actions = append(actions, Action{
			ID:          "encode-base64",
			Label:       "Encode Base64",
			Description: "Encode the current input as raw base64 without line breaks.",
		})
	}

	return actions
}

func decodeRequestBytes(b64 string) ([]byte, error) {
	if strings.TrimSpace(b64) == "" {
		return nil, fmt.Errorf("inputBase64 is required")
	}
	out, err := base64.StdEncoding.DecodeString(b64)
	if err == nil {
		return out, nil
	}
	out, err = base64.RawStdEncoding.DecodeString(b64)
	if err == nil {
		return out, nil
	}
	return nil, fmt.Errorf("inputBase64 is not valid base64")
}

func orderedPEMName(name string) string {
	base := filepath.Base(strings.TrimSpace(name))
	if base == "" {
		return "ordered-chain.pem"
	}
	ext := filepath.Ext(base)
	root := strings.TrimSuffix(base, ext)
	if root == "" {
		root = "ordered-chain"
	}
	return root + "-ordered.pem"
}

func decodedName(name string) string {
	base := filepath.Base(strings.TrimSpace(name))
	if base == "" {
		return "decoded.bin"
	}
	ext := strings.ToLower(filepath.Ext(base))
	switch ext {
	case ".b64", ".base64":
		root := strings.TrimSuffix(base, ext)
		if root != "" {
			return root
		}
	}
	return base + ".decoded"
}

func replaceExt(name, ext, fallback string) string {
	base := filepath.Base(strings.TrimSpace(name))
	if base == "" {
		return fallback
	}
	currentExt := filepath.Ext(base)
	root := strings.TrimSuffix(base, currentExt)
	if root == "" {
		root = "certconv-output"
	}
	return root + ext
}
