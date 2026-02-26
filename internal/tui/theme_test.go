package tui

import "testing"

func TestThemeByName_Fallbacks(t *testing.T) {
	if got := ThemeByName(""); got.Name != "github-dark-high-contrast" {
		t.Fatalf("expected github-dark-high-contrast (default when unconfigured), got %q", got.Name)
	}
	if got := ThemeByName("default"); got.Name != "default" {
		t.Fatalf("expected default, got %q", got.Name)
	}
	if got := ThemeByName("nope"); got.Name != "default" {
		t.Fatalf("expected default fallback, got %q", got.Name)
	}
	if got := ThemeByName("github-dark"); got.Name != "github-dark" {
		t.Fatalf("expected github-dark, got %q", got.Name)
	}
	if got := ThemeByName("github-dark-high-contrast"); got.Name != "github-dark-high-contrast" {
		t.Fatalf("expected github-dark-high-contrast, got %q", got.Name)
	}
	if got := ThemeByName("terminal"); got.Name != "terminal" {
		t.Fatalf("expected terminal, got %q", got.Name)
	}

	// Back-compat aliases should canonicalize.
	if got := ThemeByName("high-contrast"); got.Name != "github-dark-high-contrast" {
		t.Fatalf("expected alias high-contrast to map to github-dark-high-contrast, got %q", got.Name)
	}
}

func TestApplyTheme_SetsPackageVars(t *testing.T) {
	// Ensure we don't leave global state in a surprising configuration for other tests.
	defer ApplyTheme(themeDefault)

	ApplyTheme(themeGitHubDarkHighContrast)

	if accentColor != themeGitHubDarkHighContrast.Accent {
		t.Fatalf("accentColor mismatch: got %v want %v", accentColor, themeGitHubDarkHighContrast.Accent)
	}
	if dimColor != themeGitHubDarkHighContrast.Dim {
		t.Fatalf("dimColor mismatch: got %v want %v", dimColor, themeGitHubDarkHighContrast.Dim)
	}
	if textColor != themeGitHubDarkHighContrast.Text {
		t.Fatalf("textColor mismatch: got %v want %v", textColor, themeGitHubDarkHighContrast.Text)
	}
	if paneTextColor != themeGitHubDarkHighContrast.PaneText {
		t.Fatalf("paneTextColor mismatch: got %v want %v", paneTextColor, themeGitHubDarkHighContrast.PaneText)
	}
	if paneDimColor != themeGitHubDarkHighContrast.PaneDim {
		t.Fatalf("paneDimColor mismatch: got %v want %v", paneDimColor, themeGitHubDarkHighContrast.PaneDim)
	}
	if bgColor != themeGitHubDarkHighContrast.Bg {
		t.Fatalf("bgColor mismatch: got %v want %v", bgColor, themeGitHubDarkHighContrast.Bg)
	}
	if successColor != themeGitHubDarkHighContrast.Success {
		t.Fatalf("successColor mismatch: got %v want %v", successColor, themeGitHubDarkHighContrast.Success)
	}
	if errorColor != themeGitHubDarkHighContrast.Error {
		t.Fatalf("errorColor mismatch: got %v want %v", errorColor, themeGitHubDarkHighContrast.Error)
	}
}

func TestThemeNames(t *testing.T) {
	names := ThemeNames()
	if len(names) != 4 {
		t.Fatalf("expected 4 theme names, got %d", len(names))
	}
}
