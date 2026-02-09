package tui

import (
	"os"
	"strings"
	"testing"

	"github.com/nickromney/certconv/test/testutil"
)

func TestChainSummaryForFile_PEM(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	s, ok := chainSummaryForFile(pair.CertPath)
	if !ok {
		t.Fatalf("expected ok")
	}
	if !strings.Contains(s, "Chain: 1 certificate") {
		t.Fatalf("expected 1-cert chain summary, got:\n%s", s)
	}
	if !strings.Contains(s, "Subject:") || !strings.Contains(s, "Issuer:") || !strings.Contains(s, "Not After:") {
		t.Fatalf("expected fields present, got:\n%s", s)
	}
}

func TestChainSummaryFromBytes_DERFallback(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	derPath := testutil.MakeDERCert(t, pair.CertPath)
	data, err := os.ReadFile(derPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s, ok := chainSummaryFromBytes(data)
	if !ok {
		t.Fatalf("expected ok")
	}
	if !strings.Contains(s, "Chain: 1 certificate") {
		t.Fatalf("expected 1-cert chain summary, got:\n%s", s)
	}
}
