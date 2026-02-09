package tui

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/nickromney/certconv/internal/cert"
)

// renderParsedCert produces a structured text view of a certificate using
// Go's crypto/x509, independent of openssl. It covers all the fields that
// are most useful for quick inspection.
func renderParsedCert(path, password string, engine *cert.Engine, ctx context.Context) (string, error) {
	ft, err := cert.DetectType(path)
	if err != nil {
		return "", fmt.Errorf("detect type: %w", err)
	}

	var c *x509.Certificate

	switch ft {
	case cert.FileTypePFX:
		pemOut, pemErr := engine.PFXCertsPEM(ctx, path, password)
		if pemErr != nil {
			return "", pemErr
		}
		c, err = cert.ParseCertBytes(pemOut)
	case cert.FileTypeCert, cert.FileTypeCombined, cert.FileTypeDER:
		c, err = cert.ParseCertFile(path)
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
		b.WriteString(fmt.Sprintf("%-*s %s\n", labelW, k+":", v))
	}

	kvList := func(k string, items []string) {
		if len(items) == 0 {
			return
		}
		b.WriteString(fmt.Sprintf("%-*s %s\n", labelW, k+":", items[0]))
		for _, item := range items[1:] {
			b.WriteString(fmt.Sprintf("%-*s %s\n", labelW, "", item))
		}
	}

	section := func(title string) {
		b.WriteString("\n")
		b.WriteString(title + "\n")
		b.WriteString(strings.Repeat("-", len(title)) + "\n")
	}

	// Identity
	section("Identity")
	kv("Subject", c.Subject.String())
	kv("Issuer", c.Issuer.String())
	kv("Serial", formatSerial(c.SerialNumber.Bytes()))

	isSelfSigned := c.Subject.String() == c.Issuer.String()
	if isSelfSigned {
		kv("Self-Signed", "Yes")
	}

	// Validity
	section("Validity")
	kv("Not Before", c.NotBefore.Format(time.RFC3339))
	kv("Not After", c.NotAfter.Format(time.RFC3339))
	daysLeft := int(time.Until(c.NotAfter).Hours() / 24)
	if daysLeft < 0 {
		kv("Status", fmt.Sprintf("EXPIRED (%d days ago)", -daysLeft))
	} else if daysLeft <= 30 {
		kv("Status", fmt.Sprintf("Expiring soon (%d days left)", daysLeft))
	} else {
		kv("Status", fmt.Sprintf("Valid (%d days left)", daysLeft))
	}

	// Subject Alternative Names
	sans := cert.FormatSANsList(c)
	if len(sans) > 0 {
		section("Subject Alternative Names")
		for _, san := range sans {
			b.WriteString("  " + san + "\n")
		}
	}

	// Key & Signature
	section("Key & Signature")
	kv("Public Key Algorithm", c.PublicKeyAlgorithm.String())
	kv("Public Key", describePublicKeyBrief(c))
	kv("Signature Algorithm", c.SignatureAlgorithm.String())

	// Key Usage
	kuList := cert.DescribeKeyUsageList(c.KeyUsage)
	ekuList := cert.DescribeExtKeyUsageList(c.ExtKeyUsage)
	if len(kuList) > 0 || len(ekuList) > 0 {
		section("Key Usage")
		kvList("Key Usage", kuList)
		kvList("Extended Key Usage", ekuList)
	}

	// Basic Constraints
	if c.IsCA || c.BasicConstraintsValid {
		section("Basic Constraints")
		if c.IsCA {
			kv("CA", "Yes")
			if c.MaxPathLen > 0 || c.MaxPathLenZero {
				kv("Max Path Length", fmt.Sprintf("%d", c.MaxPathLen))
			}
		} else {
			kv("CA", "No")
		}
	}

	// Authority / Subject Key Identifiers
	if len(c.AuthorityKeyId) > 0 || len(c.SubjectKeyId) > 0 {
		section("Key Identifiers")
		if len(c.SubjectKeyId) > 0 {
			kv("Subject Key ID", formatHex(c.SubjectKeyId))
		}
		if len(c.AuthorityKeyId) > 0 {
			kv("Authority Key ID", formatHex(c.AuthorityKeyId))
		}
	}

	// OCSP / CRL
	if len(c.OCSPServer) > 0 || len(c.CRLDistributionPoints) > 0 || len(c.IssuingCertificateURL) > 0 {
		section("Revocation & AIA")
		kvList("OCSP Servers", c.OCSPServer)
		kvList("CRL Distribution", c.CRLDistributionPoints)
		kvList("Issuer Cert URL", c.IssuingCertificateURL)
	}

	// Fingerprints
	section("Fingerprints")
	kv("SHA-256", cert.FormatCertFingerprint(c))

	// Certificate Policies
	if len(c.PolicyIdentifiers) > 0 {
		section("Certificate Policies")
		for _, oid := range c.PolicyIdentifiers {
			b.WriteString("  " + oid.String() + "\n")
		}
	}

	return b.String(), nil
}

func describePublicKeyBrief(c *x509.Certificate) string {
	// Reuse the cert package's existing function via the summary path.
	s := &cert.CertSummary{}
	cert.EnrichSummary(s, c)
	return s.PublicKeyInfo
}

func formatSerial(raw []byte) string {
	return strings.ToUpper(hex.EncodeToString(raw))
}

func formatHex(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
