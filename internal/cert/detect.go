package cert

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var keyHeaderRE = regexp.MustCompile(`^-----BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY-----$`)
var publicKeyHeaderRE = regexp.MustCompile(`^-----BEGIN (RSA )?PUBLIC KEY-----$`)

// DetectType determines the FileType of a file by extension and content inspection.
func DetectType(path string) (FileType, error) {
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".pfx", ".p12":
		return FileTypePFX, nil
	case ".pub":
		// Common for OpenSSH public keys.
		return FileTypePublicKey, nil
	case ".der":
		return FileTypeDER, nil
	case ".b64", ".base64":
		return FileTypeBase64, nil
	}

	// For .key extension, check content first; if it has cert markers too, it's combined
	if ext == ".key" {
		hasCert, hasKey, err := scanPEMMarkers(path)
		if err != nil {
			return FileTypeKey, nil // default to key for .key extension
		}
		if hasCert && hasKey {
			return FileTypeCombined, nil
		}
		if !hasKey && hasPublicKeyMarker(path) {
			return FileTypePublicKey, nil
		}
		return FileTypeKey, nil
	}

	// Check file content for PEM markers
	hasCert, hasKey, err := scanPEMMarkers(path)
	if err != nil {
		return FileTypeUnknown, err
	}

	if hasCert && hasKey {
		return FileTypeCombined, nil
	}
	if hasCert {
		return FileTypeCert, nil
	}
	if hasKey {
		return FileTypeKey, nil
	}
	if hasPublicKeyMarker(path) {
		return FileTypePublicKey, nil
	}
	if hasOpenSSHPublicKeyMarker(path) {
		return FileTypePublicKey, nil
	}

	return FileTypeUnknown, nil
}

// scanPEMMarkers scans a file for BEGIN CERTIFICATE and BEGIN PRIVATE KEY markers.
func scanPEMMarkers(path string) (hasCert, hasKey bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return false, false, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "BEGIN CERTIFICATE") {
			hasCert = true
		}
		if keyHeaderRE.MatchString(line) {
			hasKey = true
		}
		if hasCert && hasKey {
			break
		}
	}
	return hasCert, hasKey, scanner.Err()
}

func hasPublicKeyMarker(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if publicKeyHeaderRE.MatchString(strings.TrimSpace(scanner.Text())) {
			return true
		}
	}
	return false
}

func hasOpenSSHPublicKeyMarker(path string) bool {
	line, err := ReadFirstNonEmptyLine(path)
	if err != nil {
		return false
	}
	p, err := ParseOpenSSHPublicKeyLine(line)
	return err == nil && p != nil
}

// IsDEREncoded checks if a file starts with the ASN.1 SEQUENCE tag (0x30).
func IsDEREncoded(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	buf := make([]byte, 1)
	n, err := f.Read(buf)
	if err != nil || n == 0 {
		return false, err
	}
	return buf[0] == 0x30, nil
}
