package cert

import (
	"crypto/rsa"
	"crypto/x509"
	"time"
)

// LintSeverity indicates the severity of a lint issue.
type LintSeverity string

const (
	LintError   LintSeverity = "error"
	LintWarning LintSeverity = "warning"
)

// LintIssue describes a single lint finding.
type LintIssue struct {
	Severity LintSeverity `json:"severity"`
	Code     string       `json:"code"`
	Message  string       `json:"message"`
}

// LintResult holds all lint findings for a certificate file.
type LintResult struct {
	File   string      `json:"file"`
	Issues []LintIssue `json:"issues"`
	Clean  bool        `json:"clean"`
}

// lintCheck is a single lint rule applied to a parsed certificate.
type lintCheck func(*x509.Certificate) []LintIssue

// allLintChecks returns the ordered list of lint checks.
func allLintChecks() []lintCheck {
	return []lintCheck{
		checkWeakKey,
		checkSHA1Signature,
		checkMissingSANs,
		checkExpired,
		checkNotYetValid,
		checkCAAsLeaf,
		checkLongValidity,
	}
}

// LintCertificate runs all lint checks against a parsed certificate.
func LintCertificate(c *x509.Certificate) []LintIssue {
	var issues []LintIssue
	for _, check := range allLintChecks() {
		issues = append(issues, check(c)...)
	}
	return issues
}

// LintFile parses a certificate file and runs all lint checks.
func LintFile(path string) (*LintResult, error) {
	c, err := ParseCertFile(path)
	if err != nil {
		return nil, err
	}
	issues := LintCertificate(c)
	return &LintResult{
		File:   path,
		Issues: issues,
		Clean:  len(issues) == 0,
	}, nil
}

func checkWeakKey(c *x509.Certificate) []LintIssue {
	if pub, ok := c.PublicKey.(*rsa.PublicKey); ok {
		if pub.N.BitLen() < 2048 {
			return []LintIssue{{
				Severity: LintError,
				Code:     "weak-key",
				Message:  "RSA key is less than 2048 bits",
			}}
		}
	}
	return nil
}

func checkSHA1Signature(c *x509.Certificate) []LintIssue {
	switch c.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		return []LintIssue{{
			Severity: LintWarning,
			Code:     "sha1-signature",
			Message:  "Certificate uses SHA-1 signature algorithm",
		}}
	}
	return nil
}

func checkMissingSANs(c *x509.Certificate) []LintIssue {
	if len(c.DNSNames) == 0 && len(c.IPAddresses) == 0 && len(c.EmailAddresses) == 0 && len(c.URIs) == 0 {
		return []LintIssue{{
			Severity: LintWarning,
			Code:     "missing-sans",
			Message:  "No Subject Alternative Names; relies on Common Name",
		}}
	}
	return nil
}

func checkExpired(c *x509.Certificate) []LintIssue {
	if time.Now().After(c.NotAfter) {
		return []LintIssue{{
			Severity: LintError,
			Code:     "expired",
			Message:  "Certificate has expired (NotAfter: " + c.NotAfter.UTC().Format(time.RFC3339) + ")",
		}}
	}
	return nil
}

func checkNotYetValid(c *x509.Certificate) []LintIssue {
	if time.Now().Before(c.NotBefore) {
		return []LintIssue{{
			Severity: LintError,
			Code:     "not-yet-valid",
			Message:  "Certificate is not yet valid (NotBefore: " + c.NotBefore.UTC().Format(time.RFC3339) + ")",
		}}
	}
	return nil
}

func checkCAAsLeaf(c *x509.Certificate) []LintIssue {
	if !c.IsCA {
		return nil
	}
	hasServerAuth := false
	for _, eku := range c.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}
	if !hasServerAuth {
		return nil
	}
	if c.KeyUsage&x509.KeyUsageCertSign != 0 {
		return nil
	}
	return []LintIssue{{
		Severity: LintWarning,
		Code:     "ca-as-leaf",
		Message:  "CA=true with ServerAuth EKU but missing CertSign key usage",
	}}
}

func checkLongValidity(c *x509.Certificate) []LintIssue {
	if c.IsCA {
		return nil
	}
	duration := c.NotAfter.Sub(c.NotBefore)
	if duration > 398*24*time.Hour {
		return []LintIssue{{
			Severity: LintWarning,
			Code:     "long-validity",
			Message:  "Leaf certificate validity exceeds 398 days",
		}}
	}
	return nil
}
