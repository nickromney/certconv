package tui

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
)

func chainSummaryForFile(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}

	return chainSummaryFromBytes(data)
}

func chainSummaryFromBytes(data []byte) (string, bool) {
	certs := parseCertificates(data)
	if len(certs) == 0 {
		return "", false
	}

	var b strings.Builder
	if len(certs) == 1 {
		b.WriteString("Chain: 1 certificate\n")
	} else {
		b.WriteString(fmt.Sprintf("Chain: %d certificates\n", len(certs)))
	}
	b.WriteString("\n")

	for i, c := range certs {
		b.WriteString(fmt.Sprintf("%d. Subject: %s\n", i+1, c.Subject.String()))
		b.WriteString(fmt.Sprintf("   Issuer:  %s\n", c.Issuer.String()))
		b.WriteString(fmt.Sprintf("   Not After: %s\n", c.NotAfter.Format(time.RFC3339)))
		b.WriteString("\n")
	}

	return strings.TrimRight(b.String(), "\n"), true
}

func parseCertificates(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate

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

		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, c)
	}

	// DER fallback (single cert)
	if len(certs) == 0 {
		if c, err := x509.ParseCertificate(data); err == nil {
			certs = append(certs, c)
		}
	}

	return certs
}
