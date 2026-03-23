package webapi

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"time"

	"github.com/nickromney/certconv/internal/cert"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func renderOneLine(data []byte) (string, error) {
	const maxBytes = 256 * 1024
	if len(data) > maxBytes {
		return "", fmt.Errorf("file too large for one-line view (%d bytes)", len(data))
	}

	for _, b := range data[:min(512, len(data))] {
		if b == 0 {
			return "", fmt.Errorf("binary file; use Base64 view")
		}
	}

	text := strings.ReplaceAll(string(data), "\r", "")
	text = strings.ReplaceAll(text, "\n", "")
	return text, nil
}

func renderDERBase64(data []byte) (string, error) {
	der, err := cert.CertToDERBytes(data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

func renderPFXBase64(name string, data []byte) (string, error) {
	certs, privateKey, err := parsePEMCertificatesAndKey(name, data)
	if err != nil {
		return "", err
	}
	if len(certs) == 0 {
		return "", fmt.Errorf("PFX view requires at least one certificate")
	}

	var pfx []byte
	if privateKey != nil {
		pfx, err = pkcs12.Legacy.WithRand(rand.Reader).Encode(privateKey, certs[0], certs[1:], "")
	} else {
		pfx, err = pkcs12.Legacy.WithRand(rand.Reader).EncodeTrustStore(certs, "")
	}
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(pfx), nil
}

func renderParsedCertificate(name string, data []byte, password string) (string, error) {
	ft := cert.DetectTypeFromNameAndBytes(name, data)

	var parsed *x509.Certificate
	var err error

	switch ft {
	case cert.FileTypePFX:
		parsed, _, err = cert.ParsePFXCertificates(data, password)
	case cert.FileTypeCert, cert.FileTypeCombined, cert.FileTypeDER:
		parsed, err = cert.ParseCertBytes(data)
	default:
		return "", fmt.Errorf("parsed view is only available for certificate files")
	}
	if err != nil {
		return "", err
	}

	var b strings.Builder
	const labelW = 24

	kv := func(k, v string) {
		if v == "" {
			return
		}
		fmt.Fprintf(&b, "%-*s %s\n", labelW, k+":", v)
	}

	kvList := func(k string, items []string) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(&b, "%-*s %s\n", labelW, k+":", items[0])
		for _, item := range items[1:] {
			fmt.Fprintf(&b, "%-*s %s\n", labelW, "", item)
		}
	}

	section := func(title string) {
		b.WriteString("\n")
		b.WriteString(title + "\n")
		b.WriteString(strings.Repeat("-", len(title)) + "\n")
	}

	section("Identity")
	kv("Subject", parsed.Subject.String())
	kv("Issuer", parsed.Issuer.String())
	kv("Serial", strings.ToUpper(hex.EncodeToString(parsed.SerialNumber.Bytes())))

	if parsed.Subject.String() == parsed.Issuer.String() {
		kv("Self-Signed", "Yes")
	}

	section("Validity")
	kv("Not Before", parsed.NotBefore.Format(time.RFC3339))
	kv("Not After", parsed.NotAfter.Format(time.RFC3339))
	daysLeft := int(time.Until(parsed.NotAfter).Hours() / 24)
	switch {
	case daysLeft < 0:
		kv("Status", fmt.Sprintf("EXPIRED (%d days ago)", -daysLeft))
	case daysLeft <= 30:
		kv("Status", fmt.Sprintf("Expiring soon (%d days left)", daysLeft))
	default:
		kv("Status", fmt.Sprintf("Valid (%d days left)", daysLeft))
	}

	if sans := cert.FormatSANsList(parsed); len(sans) > 0 {
		section("Subject Alternative Names")
		for _, san := range sans {
			b.WriteString("  " + san + "\n")
		}
	}

	section("Key & Signature")
	kv("Public Key Algorithm", parsed.PublicKeyAlgorithm.String())
	kv("Public Key", describePublicKeyBrief(parsed))
	kv("Signature Algorithm", parsed.SignatureAlgorithm.String())

	if kuList, ekuList := cert.DescribeKeyUsageList(parsed.KeyUsage), cert.DescribeExtKeyUsageList(parsed.ExtKeyUsage); len(kuList) > 0 || len(ekuList) > 0 {
		section("Key Usage")
		kvList("Key Usage", kuList)
		kvList("Extended Key Usage", ekuList)
	}

	if parsed.IsCA || parsed.BasicConstraintsValid {
		section("Basic Constraints")
		if parsed.IsCA {
			kv("CA", "Yes")
			if parsed.MaxPathLen > 0 || parsed.MaxPathLenZero {
				kv("Max Path Length", fmt.Sprintf("%d", parsed.MaxPathLen))
			}
		} else {
			kv("CA", "No")
		}
	}

	if len(parsed.AuthorityKeyId) > 0 || len(parsed.SubjectKeyId) > 0 {
		section("Key Identifiers")
		if len(parsed.SubjectKeyId) > 0 {
			kv("Subject Key ID", formatHex(parsed.SubjectKeyId))
		}
		if len(parsed.AuthorityKeyId) > 0 {
			kv("Authority Key ID", formatHex(parsed.AuthorityKeyId))
		}
	}

	if len(parsed.OCSPServer) > 0 || len(parsed.CRLDistributionPoints) > 0 || len(parsed.IssuingCertificateURL) > 0 {
		section("Revocation & AIA")
		kvList("OCSP Servers", parsed.OCSPServer)
		kvList("CRL Distribution", parsed.CRLDistributionPoints)
		kvList("Issuer Cert URL", parsed.IssuingCertificateURL)
	}

	section("Fingerprints")
	kv("SHA-256", cert.FormatCertFingerprint(parsed))

	if len(parsed.PolicyIdentifiers) > 0 {
		section("Certificate Policies")
		for _, oid := range parsed.PolicyIdentifiers {
			b.WriteString("  " + oid.String() + "\n")
		}
	}

	return b.String(), nil
}

func renderRSAModulus(name string, data []byte) (string, error) {
	modulus, err := rsaModulusFromBytes(name, data)
	if err != nil {
		return "", err
	}

	modulusHex := strings.ToUpper(modulus.Text(16))
	sha, md := cert.ModulusDigestsHex(modulusHex)

	var b strings.Builder
	b.WriteString("Modulus (hex):\n")
	b.WriteString(wrapFixed(modulusHex, 64))
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "%-18s %s\n", "SHA256(modulus):", sha)
	fmt.Fprintf(&b, "%-18s %s\n", "MD5(modulus):", md)
	return b.String(), nil
}

func rsaModulusFromBytes(name string, data []byte) (*big.Int, error) {
	switch cert.DetectTypeFromNameAndBytes(name, data) {
	case cert.FileTypeCert, cert.FileTypeCombined, cert.FileTypeDER:
		parsed, err := cert.ParseCertBytes(data)
		if err != nil {
			return nil, err
		}
		pub, ok := parsed.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, cert.ErrNotRSA
		}
		return pub.N, nil
	case cert.FileTypeKey:
		return rsaPrivateModulusFromPEM(data)
	default:
		return nil, fmt.Errorf("RSA modulus view is not available for %s files", cert.DetectTypeFromNameAndBytes(name, data))
	}
}

func rsaPrivateModulusFromPEM(data []byte) (*big.Int, error) {
	rest := data
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remainder

		switch block.Type {
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			return key.N, nil
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, cert.ErrNotRSA
			}
			return rsaKey.N, nil
		case "EC PRIVATE KEY":
			return nil, cert.ErrNotRSA
		case "ENCRYPTED PRIVATE KEY":
			return nil, fmt.Errorf("encrypted private keys are not supported in the browser build")
		}
	}

	return nil, fmt.Errorf("could not parse an RSA private key")
}

func parsePEMCertificatesAndKey(name string, data []byte) ([]*x509.Certificate, any, error) {
	ft := cert.DetectTypeFromNameAndBytes(name, data)
	if ft != cert.FileTypeCert && ft != cert.FileTypeCombined {
		return nil, nil, fmt.Errorf("PFX view is only available for PEM certificate inputs")
	}

	var certs []*x509.Certificate
	var privateKey any

	rest := data
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remainder

		switch block.Type {
		case "CERTIFICATE":
			parsed, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			certs = append(certs, parsed)
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			privateKey = key
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			privateKey = key
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			privateKey = key
		case "ENCRYPTED PRIVATE KEY":
			return nil, nil, fmt.Errorf("encrypted private keys are not supported in the browser build")
		}
	}

	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("could not find a certificate in this PEM input")
	}

	return certs, privateKey, nil
}

func wrapFixed(s string, width int) string {
	if width <= 0 || s == "" {
		return s
	}

	var b strings.Builder
	for i := 0; i < len(s); i += width {
		if i > 0 {
			b.WriteByte('\n')
		}
		end := i + width
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
	}
	return b.String()
}

func describePublicKeyBrief(parsed *x509.Certificate) string {
	switch pub := parsed.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		if pub.Curve == nil || pub.Params() == nil {
			return "ECDSA"
		}
		return fmt.Sprintf("ECDSA %s", pub.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return parsed.PublicKeyAlgorithm.String()
	}
}

func formatHex(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func outputNameForView(name, suffix string) string {
	base := filepath.Base(strings.TrimSpace(name))
	if base == "" {
		return suffix
	}
	return base + "." + suffix
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
