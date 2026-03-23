package cert

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// DetectTypeFromNameAndBytes determines the file type from a filename hint and
// in-memory contents. This is the browser-safe counterpart to DetectType.
func DetectTypeFromNameAndBytes(name string, data []byte) FileType {
	ext := strings.ToLower(filepath.Ext(name))

	switch ext {
	case ".pfx", ".p12":
		return FileTypePFX
	case ".pub":
		return FileTypePublicKey
	case ".der":
		if _, err := x509.ParseCertificate(data); err == nil {
			return FileTypeDER
		}
	case ".b64", ".base64":
		return FileTypeBase64
	case ".p7b", ".p7c":
		return FileTypeP7B
	}

	hasCert, hasKey := scanPEMMarkersBytes(data)
	if hasCert && hasKey {
		return FileTypeCombined
	}
	if hasCert {
		return FileTypeCert
	}
	if hasKey {
		return FileTypeKey
	}
	if hasPublicKeyMarkerBytes(data) || hasOpenSSHPublicKeyMarkerBytes(data) {
		return FileTypePublicKey
	}
	if _, err := x509.ParseCertificate(data); err == nil {
		return FileTypeDER
	}
	if looksLikeBase64Bytes(data) {
		return FileTypeBase64
	}
	return FileTypeUnknown
}

// SummaryFromBytes returns a pure-Go summary for browser and API use.
func SummaryFromBytes(name string, data []byte) (*CertSummary, error) {
	return SummaryFromBytesWithPassword(name, data, "")
}

// SummaryFromBytesWithPassword returns a pure-Go summary for browser and API
// use, including password-protected PFX/P12 containers.
func SummaryFromBytesWithPassword(name string, data []byte, password string) (*CertSummary, error) {
	ft := DetectTypeFromNameAndBytes(name, data)
	s := &CertSummary{
		File:     name,
		FileType: ft,
	}

	switch ft {
	case FileTypeCert, FileTypeCombined, FileTypeDER:
		c, err := ParseCertBytes(data)
		if err != nil {
			return s, err
		}
		populateSummaryFromCertificate(s, c)
		return s, nil

	case FileTypePFX:
		c, _, err := ParsePFXCertificates(data, password)
		if err != nil {
			return s, err
		}
		populateSummaryFromCertificate(s, c)
		return s, nil

	case FileTypeKey:
		s.KeyType = detectKeyTypeBytes(data)
		return s, nil

	case FileTypePublicKey:
		line, err := ReadFirstNonEmptyLineBytes(data)
		if err == nil {
			if pk, pkErr := ParseOpenSSHPublicKeyLine(line); pkErr == nil && pk != nil {
				s.PublicKeyAlgorithm = pk.Algorithm
				s.PublicKeyComment = pk.Comment
				return s, nil
			}
		}
		if algo := describePEMPublicKeyBytes(data); algo != "" {
			s.PublicKeyAlgorithm = algo
		}
		return s, nil

	default:
		return s, nil
	}
}

// LintBytes parses certificate bytes and runs lint rules.
func LintBytes(name string, data []byte) (*LintResult, error) {
	return LintBytesWithPassword(name, data, "")
}

// LintBytesWithPassword parses certificate bytes and runs lint rules,
// including extracting the leaf certificate from password-protected PFX/P12
// containers.
func LintBytesWithPassword(name string, data []byte, password string) (*LintResult, error) {
	ft := DetectTypeFromNameAndBytes(name, data)

	if ft == FileTypePFX {
		c, _, err := ParsePFXCertificates(data, password)
		if err != nil {
			return nil, err
		}
		issues := LintCertificate(c)
		return &LintResult{
			File:   name,
			Issues: issues,
			Clean:  len(issues) == 0,
		}, nil
	}

	c, err := ParseCertBytes(data)
	if err != nil {
		return nil, err
	}
	issues := LintCertificate(c)
	return &LintResult{
		File:   name,
		Issues: issues,
		Clean:  len(issues) == 0,
	}, nil
}

// CountPEMCertificates returns the number of CERTIFICATE blocks in PEM data.
func CountPEMCertificates(data []byte) int {
	count := 0
	rest := data
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			return count
		}
		rest = r
		if block.Type == "CERTIFICATE" {
			count++
		}
	}
}

// ParsePFXCertificates extracts the primary certificate and any additional
// chain certificates from a DER-encoded PKCS#12/PFX container.
func ParsePFXCertificates(data []byte, password string) (*x509.Certificate, []*x509.Certificate, error) {
	_, cert, caCerts, err := pkcs12.DecodeChain(data, password)
	if err == nil {
		certs := append([]*x509.Certificate{cert}, caCerts...)
		return cert, certs, nil
	}

	if errors.Is(err, pkcs12.ErrIncorrectPassword) || errors.Is(err, pkcs12.ErrDecryption) {
		return nil, nil, fmt.Errorf("%w: %s", ErrPFXIncorrectPassword, err.Error())
	}

	trustCerts, trustErr := pkcs12.DecodeTrustStore(data, password)
	if trustErr == nil && len(trustCerts) > 0 {
		return trustCerts[0], trustCerts, nil
	}

	return nil, nil, classifyPFXBytesError(err, trustErr)
}

// CertToDERBytes converts a PEM or combined PEM certificate to DER bytes.
func CertToDERBytes(data []byte) ([]byte, error) {
	c, err := ParseCertBytes(data)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), c.Raw...), nil
}

// CertFromDERBytes converts DER certificate bytes to PEM.
func CertFromDERBytes(data []byte) ([]byte, error) {
	c, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	if len(out) == 0 {
		return nil, fmt.Errorf("failed to encode PEM certificate")
	}
	return out, nil
}

// ToBase64Bytes encodes bytes as raw base64 without line breaks.
func ToBase64Bytes(data []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(data))
}

// FromBase64Bytes decodes a raw base64 payload to bytes.
func FromBase64Bytes(data []byte) ([]byte, error) {
	content := compactWhitespace(string(data))
	if content == "" {
		return nil, fmt.Errorf("base64 input is empty")
	}
	if strings.Contains(content, "-----BEGIN") {
		return nil, fmt.Errorf("input appears to be PEM, not raw base64")
	}

	decoded, err := base64.StdEncoding.DecodeString(content)
	if err == nil {
		return decoded, nil
	}
	decoded, err = base64.RawStdEncoding.DecodeString(content)
	if err == nil {
		return decoded, nil
	}
	return nil, fmt.Errorf("base64 decoding failed")
}

// ReadFirstNonEmptyLineBytes returns the first non-empty trimmed line in a byte
// slice.
func ReadFirstNonEmptyLineBytes(data []byte) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		return line, nil
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("empty input")
}

func populateSummaryFromCertificate(s *CertSummary, c *x509.Certificate) {
	if s == nil || c == nil {
		return
	}
	s.Subject = c.Subject.String()
	s.Issuer = c.Issuer.String()
	s.NotBefore = c.NotBefore.UTC().Format(time.RFC3339)
	s.NotAfter = c.NotAfter.UTC().Format(time.RFC3339)
	s.Serial = strings.ToUpper(c.SerialNumber.Text(16))
	EnrichSummary(s, c)
}

func scanPEMMarkersBytes(data []byte) (hasCert, hasKey bool) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.Contains(line, "BEGIN CERTIFICATE") {
			hasCert = true
		}
		if keyHeaderRE.MatchString(line) {
			hasKey = true
		}
		if hasCert && hasKey {
			return hasCert, hasKey
		}
	}
	return hasCert, hasKey
}

func hasPublicKeyMarkerBytes(data []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if publicKeyHeaderRE.MatchString(strings.TrimSpace(sc.Text())) {
			return true
		}
	}
	return false
}

func hasOpenSSHPublicKeyMarkerBytes(data []byte) bool {
	line, err := ReadFirstNonEmptyLineBytes(data)
	if err != nil {
		return false
	}
	p, err := ParseOpenSSHPublicKeyLine(line)
	return err == nil && p != nil
}

func detectKeyTypeBytes(data []byte) KeyType {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "RSA PRIVATE KEY") {
			return KeyTypeRSA
		}
		if strings.Contains(line, "EC PRIVATE KEY") {
			return KeyTypeEC
		}
	}
	return KeyTypePKCS8
}

func describePEMPublicKeyBytes(data []byte) string {
	rest := data
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			return ""
		}
		rest = r
		switch block.Type {
		case "PUBLIC KEY":
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				continue
			}
			return describePublicKeyValue(pub)
		case "RSA PUBLIC KEY":
			pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				continue
			}
			return describePublicKeyValue(pub)
		}
	}
}

func describePublicKeyValue(pub any) string {
	switch v := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", v.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", curveName(v.Curve))
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return "PEM"
	}
}

func looksLikeBase64Bytes(data []byte) bool {
	content := compactWhitespace(string(data))
	if content == "" || strings.Contains(content, "-----BEGIN") {
		return false
	}
	if _, err := base64.StdEncoding.DecodeString(content); err == nil {
		return true
	}
	if _, err := base64.RawStdEncoding.DecodeString(content); err == nil {
		return true
	}
	return false
}

func compactWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
