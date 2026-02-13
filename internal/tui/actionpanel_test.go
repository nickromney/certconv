package tui

import (
	"testing"

	"github.com/nickromney/certconv/internal/cert"
)

func TestActionPanel_SetActions_CertOrderAndKeys(t *testing.T) {
	ap := newActionPanel()
	ap.SetActions(cert.FileTypeCert)

	want := []action{
		{Name: "Encode to Base64", Key: "b", ID: "to-base64"},
		{Name: "Convert to DER", Key: "d", ID: "to-der"},
		{Name: "Check Expiry", Key: "e", ID: "expiry"},
		{Name: "Combine with Key", Key: "k", ID: "combine"},
		{Name: "Match Key", Key: "m", ID: "match"},
		{Name: "Convert to PFX", Key: "p", ID: "to-pfx"},
		{Name: "Verify Chain", Key: "v", ID: "verify"},
	}

	if len(ap.actions) != len(want) {
		t.Fatalf("expected %d actions, got %d", len(want), len(ap.actions))
	}
	for i := range want {
		if ap.actions[i] != want[i] {
			t.Fatalf("action[%d]: expected %+v, got %+v", i, want[i], ap.actions[i])
		}
	}
}

func TestActionPanel_SetActions_NoNumericShortcuts(t *testing.T) {
	ap := newActionPanel()
	fileTypes := []cert.FileType{
		cert.FileTypeCert,
		cert.FileTypeCombined,
		cert.FileTypePFX,
		cert.FileTypeDER,
		cert.FileTypeKey,
		cert.FileTypePublicKey,
		cert.FileTypeBase64,
		cert.FileTypeUnknown,
	}

	for _, ft := range fileTypes {
		ap.SetActions(ft)
		for _, a := range ap.actions {
			if a.Key == "1" || a.Key == "2" || a.Key == "3" || a.Key == "4" {
				t.Fatalf("unexpected numeric shortcut for %q action %q", ft, a.Name)
			}
		}
	}
}
