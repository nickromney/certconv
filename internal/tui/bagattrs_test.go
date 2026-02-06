package tui

import (
	"strings"
	"testing"
)

func TestStripBagAttributes_RemovesBlock(t *testing.T) {
	in := "Bag Attributes\nfriendlyName: x\nlocalKeyID: 01\n-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"
	out := stripBagAttributes(in)
	if out == in {
		t.Fatalf("expected bag attributes to be stripped")
	}
	if strings.Contains(out, "Bag Attributes") {
		t.Fatalf("expected no 'Bag Attributes' in output, got: %q", out)
	}
	if !strings.Contains(out, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("expected PEM content preserved, got: %q", out)
	}
}

func TestStripBagAttributes_NoChangeWhenAbsent(t *testing.T) {
	in := "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"
	out := stripBagAttributes(in)
	if out != in {
		t.Fatalf("expected unchanged output")
	}
}
