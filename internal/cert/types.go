package cert

import "time"

// FileType represents the detected type of a certificate-related file.
type FileType string

const (
	FileTypeCert      FileType = "cert"
	FileTypeKey       FileType = "key"
	FileTypePublicKey FileType = "public-key"
	FileTypeCombined  FileType = "combined"
	FileTypePFX       FileType = "pfx"
	FileTypeDER       FileType = "der"
	FileTypeBase64    FileType = "base64"
	FileTypeUnknown   FileType = "unknown"
)

// KeyType represents the type of a private key.
type KeyType string

const (
	KeyTypeRSA   KeyType = "RSA"
	KeyTypeEC    KeyType = "EC"
	KeyTypePKCS8 KeyType = "PKCS#8"
)

// CertSummary holds the basic properties parsed from a certificate.
type CertSummary struct {
	File      string
	FileType  FileType
	Subject   string
	Issuer    string
	NotBefore string
	NotAfter  string
	Serial    string
	// For key files
	KeyType KeyType
	// For public key files (PEM or OpenSSH).
	PublicKeyAlgorithm string // e.g. "ssh-ed25519"
	PublicKeyComment   string
}

// CertDetails holds the full text output from openssl x509 -text.
type CertDetails struct {
	File     string
	FileType FileType
	RawText  string
}

// ExpiryResult holds the result of an expiry check.
type ExpiryResult struct {
	ExpiryDate string
	ExpiresAt  time.Time
	DaysLeft   int
	Valid      bool // true if cert is valid for the checked period
}

// VerifyResult holds the result of a chain verification.
type VerifyResult struct {
	Valid   bool
	Output  string
	Details string // additional diagnostic info
}

// MatchResult holds the result of a key-to-cert match check.
type MatchResult struct {
	Match bool
}

// FromPFXResult holds the output paths from a PFX extraction.
type FromPFXResult struct {
	CertFile string
	KeyFile  string
	CAFile   string // empty if no CA certs found
}
