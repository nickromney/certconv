package config

import "testing"

func TestParseYAMLSubset_TopLevelAndKeysSection(t *testing.T) {
	in := []byte(`
# comment
certs_dir: /tmp/certs
auto_match_key: false
one_line_wrap_width: 80
mouse: false

keys:
  next_view: x
  prev_view: y
  copy: z
`)

	got, err := parseYAMLSubset(in)
	if err != nil {
		t.Fatalf("parseYAMLSubset error: %v", err)
	}
	if got.CertsDir != "/tmp/certs" {
		t.Fatalf("certs_dir: got %q", got.CertsDir)
	}
	if got.AutoMatchKey != false || !got.autoMatchSet {
		t.Fatalf("auto_match_key: got %v set=%v", got.AutoMatchKey, got.autoMatchSet)
	}
	if got.OneLineWrapWidth != 80 {
		t.Fatalf("one_line_wrap_width: got %d", got.OneLineWrapWidth)
	}
	if got.Mouse != false || !got.mouseSet {
		t.Fatalf("mouse: got %v set=%v", got.Mouse, got.mouseSet)
	}
	if got.Keys.NextView != "x" || got.Keys.PrevView != "y" || got.Keys.Copy != "z" {
		t.Fatalf("keys: got %+v", got.Keys)
	}
}

func TestParseYAMLSubset_DefaultsAutoMatchWhenUnset(t *testing.T) {
	in := []byte("one_line_wrap_width: 64\n")
	got, err := parseYAMLSubset(in)
	if err != nil {
		t.Fatalf("parseYAMLSubset error: %v", err)
	}
	if got.autoMatchSet {
		t.Fatalf("expected autoMatchSet false")
	}
	if got.AutoMatchKey != Default().AutoMatchKey {
		t.Fatalf("expected AutoMatchKey default %v, got %v", Default().AutoMatchKey, got.AutoMatchKey)
	}
}

func TestParseYAMLSubset_DefaultsMouseWhenUnset(t *testing.T) {
	in := []byte("one_line_wrap_width: 64\n")
	got, err := parseYAMLSubset(in)
	if err != nil {
		t.Fatalf("parseYAMLSubset error: %v", err)
	}
	if got.mouseSet {
		t.Fatalf("expected mouseSet false")
	}
	if got.Mouse != Default().Mouse {
		t.Fatalf("expected Mouse default %v, got %v", Default().Mouse, got.Mouse)
	}
}
