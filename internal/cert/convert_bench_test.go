package cert

import (
	"context"
	"os"
	"testing"

	"github.com/nickromney/certconv/test/testutil"
)

// The cert DER<->PEM conversions run in-process (crypto/x509) with openssl
// only as a fallback. These benchmarks document what that buys: the
// subprocess benchmark measures the old always-openssl path.

func BenchmarkCertToDER_InProcess(b *testing.B) {
	pair := testutil.MakeCertPair(b)
	pemData, err := os.ReadFile(pair.CertPath)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := CertToDERBytes(pemData); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCertToDER_OpenSSLSubprocess(b *testing.B) {
	pair := testutil.MakeCertPair(b)
	exec := &OSExecutor{}
	ctx := context.Background()

	// Skip rather than fail on machines without openssl.
	if _, _, err := exec.Run(ctx, "version"); err != nil {
		b.Skipf("openssl unavailable: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := exec.Run(ctx, "x509", "-in", pair.CertPath, "-inform", "PEM", "-outform", "DER"); err != nil {
			b.Fatal(err)
		}
	}
}
