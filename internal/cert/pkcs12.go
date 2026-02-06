package cert

import (
	"context"
	"strings"
)

// runPKCS12 runs "openssl pkcs12 ..." and transparently retries with -legacy
// when OpenSSL 3 fails to load older (legacy) PKCS#12 ciphers.
func (e *Engine) runPKCS12(ctx context.Context, args ...string) (stdout, stderr []byte, err error) {
	if len(args) == 0 || args[0] != "pkcs12" {
		return e.exec.Run(ctx, args...)
	}

	stdout, stderr, err = e.exec.Run(ctx, args...)
	if err == nil {
		return stdout, stderr, nil
	}

	// Only retry when OpenSSL indicates a provider/cipher fetch failure.
	if hasArg(args, "-legacy") || !isPKCS12LegacyProviderError(stderr) {
		return stdout, stderr, err
	}

	legacyArgs := append([]string{"pkcs12", "-legacy"}, args[1:]...)
	return e.exec.Run(ctx, legacyArgs...)
}

func hasArg(args []string, arg string) bool {
	for _, a := range args {
		if a == arg {
			return true
		}
	}
	return false
}

func isPKCS12LegacyProviderError(stderr []byte) bool {
	// Example OpenSSL 3 failure for older PKCS#12:
	// ... inner_evp_generic_fetch:unsupported
	// ... digital envelope routines:inner_evp_generic_fetch:unsup
	lower := strings.ToLower(string(stderr))
	if strings.Contains(lower, "inner_evp_generic_fetch:unsupported") {
		return true
	}
	if strings.Contains(lower, "inner_evp_generic_fetch:unsup") {
		return true
	}
	return false
}
