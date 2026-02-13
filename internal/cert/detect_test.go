package cert

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectType_ByExtension(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		content  string
		want     FileType
	}{
		{"pfx extension", "test.pfx", "binary", FileTypePFX},
		{"p12 extension", "test.p12", "binary", FileTypePFX},
		{"der extension", "test.der", "binary", FileTypeDER},
		{"pub extension", "id_ed25519.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATnq5llxM85EAvJmIsY5c8J9oHhncfvF4o0xNQpRkQ test@example", FileTypePublicKey},
		{"b64 extension", "test.b64", "data", FileTypeBase64},
		{"base64 extension", "test.base64", "data", FileTypeBase64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tt.filename)
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatalf("write test file: %v", err)
			}

			got, err := DetectType(path)
			if err != nil {
				t.Fatalf("DetectType() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("DetectType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetectType_ByContent(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    FileType
	}{
		{
			"cert only",
			"-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIUZ\n-----END CERTIFICATE-----\n",
			FileTypeCert,
		},
		{
			"key only",
			"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK\n-----END RSA PRIVATE KEY-----\n",
			FileTypeKey,
		},
		{
			"combined cert+key",
			"-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIUZ\n-----END CERTIFICATE-----\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK\n-----END RSA PRIVATE KEY-----\n",
			FileTypeCombined,
		},
		{
			"ec key",
			"-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE\n-----END EC PRIVATE KEY-----\n",
			FileTypeKey,
		},
		{
			"pkcs8 key",
			"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg\n-----END PRIVATE KEY-----\n",
			FileTypeKey,
		},
		{
			"encrypted key",
			"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFHzBJBg\n-----END ENCRYPTED PRIVATE KEY-----\n",
			FileTypeKey,
		},
		{
			"public key",
			"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----\n",
			FileTypePublicKey,
		},
		{
			"unknown content",
			"just some random text\n",
			FileTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "test.pem")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatalf("write test file: %v", err)
			}

			got, err := DetectType(path)
			if err != nil {
				t.Fatalf("DetectType() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("DetectType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetectType_KeyExtensionWithCert(t *testing.T) {
	dir := t.TempDir()
	// A .key file that also has a cert is "combined"
	path := filepath.Join(dir, "weird.key")
	content := "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIUZ\n-----END CERTIFICATE-----\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK\n-----END RSA PRIVATE KEY-----\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	got, err := DetectType(path)
	if err != nil {
		t.Fatalf("DetectType() error = %v", err)
	}
	if got != FileTypeCombined {
		t.Errorf("DetectType() = %v, want combined", got)
	}
}

func TestIsDEREncoded(t *testing.T) {
	dir := t.TempDir()

	// DER starts with 0x30 (ASN.1 SEQUENCE)
	derPath := filepath.Join(dir, "test.der")
	if err := os.WriteFile(derPath, []byte{0x30, 0x82, 0x01, 0x22}, 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	isDER, err := IsDEREncoded(derPath)
	if err != nil {
		t.Fatalf("IsDEREncoded() error = %v", err)
	}
	if !isDER {
		t.Error("IsDEREncoded() = false, want true")
	}

	// Non-DER
	pemPath := filepath.Join(dir, "test.pem")
	if err := os.WriteFile(pemPath, []byte("-----BEGIN CERTIFICATE-----"), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	isDER, err = IsDEREncoded(pemPath)
	if err != nil {
		t.Fatalf("IsDEREncoded() error = %v", err)
	}
	if isDER {
		t.Error("IsDEREncoded() = true, want false")
	}
}

func TestIsDEREncoded_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty")
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	_, err := IsDEREncoded(path)
	// Empty file should return error (EOF)
	if err == nil {
		t.Error("expected error for empty file")
	}
}
