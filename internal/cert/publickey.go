package cert

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

type OpenSSHPublicKey struct {
	Algorithm string
	Base64    string
	Comment   string
	RawLine   string
}

func ParseOpenSSHPublicKeyLine(line string) (*OpenSSHPublicKey, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("empty")
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil, fmt.Errorf("not an OpenSSH public key (expected: <algo> <base64> [comment])")
	}

	algo := parts[0]
	if !looksLikeOpenSSHPublicKeyAlgo(algo) {
		return nil, fmt.Errorf("not an OpenSSH public key algorithm: %s", algo)
	}

	b64 := parts[1]
	if _, err := base64.StdEncoding.DecodeString(b64); err != nil {
		// Some tooling emits unpadded; accept RawStdEncoding too.
		if _, err2 := base64.RawStdEncoding.DecodeString(b64); err2 != nil {
			return nil, fmt.Errorf("invalid base64 payload")
		}
	}

	comment := ""
	if len(parts) > 2 {
		comment = strings.Join(parts[2:], " ")
	}

	return &OpenSSHPublicKey{
		Algorithm: algo,
		Base64:    b64,
		Comment:   comment,
		RawLine:   line,
	}, nil
}

func ReadFirstNonEmptyLine(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
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
	return "", fmt.Errorf("empty file")
}

func looksLikeOpenSSHPublicKeyAlgo(algo string) bool {
	// Common OpenSSH public key algorithms.
	switch {
	case strings.HasPrefix(algo, "ssh-"):
		return true
	case strings.HasPrefix(algo, "ecdsa-sha2-"):
		return true
	case strings.HasPrefix(algo, "sk-"):
		return true
	default:
		return false
	}
}

func openSSHSHA256FingerprintFromBase64(b64 string) (string, int, error) {
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			return "", 0, err
		}
	}
	sum := sha256.Sum256(decoded)
	fp := base64.RawStdEncoding.EncodeToString(sum[:])
	return "SHA256:" + fp, len(decoded), nil
}
