package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// ParseCertFile reads a PEM or DER certificate file and returns the first
// parsed x509.Certificate. This is used for rich summary data without
// calling openssl.
func ParseCertFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCertBytes(data)
}

// ParseCertBytes parses the first certificate from PEM or raw DER bytes.
func ParseCertBytes(data []byte) (*x509.Certificate, error) {
	// Try PEM first.
	rest := data
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = r
		if block.Type != "CERTIFICATE" {
			continue
		}
		return x509.ParseCertificate(block.Bytes)
	}

	// DER fallback.
	return x509.ParseCertificate(data)
}

// EnrichSummary populates the crypto/x509 parsed fields on a CertSummary.
func EnrichSummary(s *CertSummary, c *x509.Certificate) {
	if s == nil || c == nil {
		return
	}

	s.SANs = collectSANs(c)
	s.SignatureAlgorithm = c.SignatureAlgorithm.String()
	s.PublicKeyInfo = describePublicKey(c)
	s.KeyUsage = describeKeyUsage(c.KeyUsage)
	s.ExtKeyUsage = describeExtKeyUsage(c.ExtKeyUsage)
	s.IsCA = c.IsCA
	s.IsSelfSigned = c.Subject.String() == c.Issuer.String()

	fp := sha256.Sum256(c.Raw)
	s.Fingerprint = formatFingerprint(hex.EncodeToString(fp[:]))
}

func collectSANs(c *x509.Certificate) []string {
	var sans []string
	sans = append(sans, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, c.EmailAddresses...)
	for _, uri := range c.URIs {
		sans = append(sans, uri.String())
	}
	return sans
}

func describePublicKey(c *x509.Certificate) string {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", curveName(pub.Curve))
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return c.PublicKeyAlgorithm.String()
	}
}

func curveName(c elliptic.Curve) string {
	if c == nil {
		return "unknown"
	}
	return c.Params().Name
}

func describeKeyUsage(ku x509.KeyUsage) []string {
	var usages []string
	names := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "Digital Signature"},
		{x509.KeyUsageContentCommitment, "Content Commitment"},
		{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
		{x509.KeyUsageDataEncipherment, "Data Encipherment"},
		{x509.KeyUsageKeyAgreement, "Key Agreement"},
		{x509.KeyUsageCertSign, "Certificate Sign"},
		{x509.KeyUsageCRLSign, "CRL Sign"},
		{x509.KeyUsageEncipherOnly, "Encipher Only"},
		{x509.KeyUsageDecipherOnly, "Decipher Only"},
	}
	for _, n := range names {
		if ku&n.bit != 0 {
			usages = append(usages, n.name)
		}
	}
	return usages
}

func describeExtKeyUsage(ekus []x509.ExtKeyUsage) []string {
	var usages []string
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                        "Any",
		x509.ExtKeyUsageServerAuth:                 "Server Auth",
		x509.ExtKeyUsageClientAuth:                 "Client Auth",
		x509.ExtKeyUsageCodeSigning:                "Code Signing",
		x509.ExtKeyUsageEmailProtection:            "Email Protection",
		x509.ExtKeyUsageIPSECEndSystem:             "IPSEC End System",
		x509.ExtKeyUsageIPSECTunnel:                "IPSEC Tunnel",
		x509.ExtKeyUsageIPSECUser:                  "IPSEC User",
		x509.ExtKeyUsageTimeStamping:               "Time Stamping",
		x509.ExtKeyUsageOCSPSigning:                "OCSP Signing",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto: "MS Server Gated Crypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:  "NS Server Gated Crypto",
	}
	for _, eku := range ekus {
		if name, ok := names[eku]; ok {
			usages = append(usages, name)
		} else {
			usages = append(usages, fmt.Sprintf("Unknown (%d)", eku))
		}
	}
	return usages
}

func formatFingerprint(hex string) string {
	var parts []string
	for i := 0; i < len(hex); i += 2 {
		end := i + 2
		if end > len(hex) {
			end = len(hex)
		}
		parts = append(parts, strings.ToUpper(hex[i:end]))
	}
	return strings.Join(parts, ":")
}

// FormatSANsShort returns a compact one-line summary of SANs for display
// in the summary pane. Long lists are truncated.
func FormatSANsShort(sans []string) string {
	if len(sans) == 0 {
		return ""
	}
	const maxShow = 3
	shown := sans
	suffix := ""
	if len(sans) > maxShow {
		shown = sans[:maxShow]
		suffix = fmt.Sprintf(" (+%d more)", len(sans)-maxShow)
	}
	return strings.Join(shown, ", ") + suffix
}

// FormatSANsList returns all SANs with type prefixes for the parsed view.
func FormatSANsList(c *x509.Certificate) []string {
	var sans []string
	for _, dns := range c.DNSNames {
		sans = append(sans, "DNS: "+dns)
	}
	for _, ip := range c.IPAddresses {
		sans = append(sans, "IP: "+ip.String())
	}
	for _, email := range c.EmailAddresses {
		sans = append(sans, "Email: "+email)
	}
	for _, uri := range c.URIs {
		sans = append(sans, "URI: "+uri.String())
	}
	return sans
}

// DescribeKeyUsageList returns key usage flags as a string slice.
func DescribeKeyUsageList(ku x509.KeyUsage) []string {
	return describeKeyUsage(ku)
}

// DescribeExtKeyUsageList returns extended key usage values as a string slice.
func DescribeExtKeyUsageList(ekus []x509.ExtKeyUsage) []string {
	return describeExtKeyUsage(ekus)
}

// FormatCertFingerprint returns the SHA-256 fingerprint of a certificate in
// colon-separated hex format.
func FormatCertFingerprint(c *x509.Certificate) string {
	fp := sha256.Sum256(c.Raw)
	return formatFingerprint(hex.EncodeToString(fp[:]))
}
