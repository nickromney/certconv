package tui

import (
	"github.com/nickromney/certconv/internal/cert"
)

// FileSelectedMsg is sent when a file is activated/selected (enter, or external picker).
type FileSelectedMsg struct {
	Path string
}

// FileFocusedMsg is sent when the cursor moves onto a file in the file pane.
// The app may debounce this to avoid doing expensive work on every key repeat.
type FileFocusedMsg struct {
	Path string
}

// FileFocusDebouncedMsg is sent after the debounce timer fires.
type FileFocusDebouncedMsg struct {
	Path string
	Seq  int
}

// FileContentMsg carries the raw file content for display.
type FileContentMsg struct {
	Path    string
	Content string
	Err     error
}

// ContentOneLineMsg carries a one-line string form of a file.
type ContentOneLineMsg struct {
	Path string
	Text string
	// AlreadySingleLine indicates the original file content did not contain newlines.
	// In that case, the UI may choose to wrap the display for readability while
	// preserving CopyText as a single line.
	AlreadySingleLine bool
	Err               error
}

// ContentBase64Msg carries a base64 form of a file.
type ContentBase64Msg struct {
	Path string
	Text string
	Err  error
}

// ContentDERBase64Msg carries a base64 form of the DER conversion of a file.
// This is a preview-only conversion (no files are written).
type ContentDERBase64Msg struct {
	Path string
	Text string
	Err  error
}

// ContentPFXBase64Msg carries a base64 form of a PFX conversion of a PEM cert + key.
// This is a preview-only conversion (no files are written).
type ContentPFXBase64Msg struct {
	Path string
	Text string
	Err  error
}

// ContentParsedMsg carries Go crypto/x509 parsed certificate data.
type ContentParsedMsg struct {
	Path string
	Text string
	Err  error
}

// ContentModulusMsg carries RSA modulus information (and optional match result).
type ContentModulusMsg struct {
	Path string
	Text string
	Err  error
}

// CertSummaryMsg carries the parsed cert summary.
type CertSummaryMsg struct {
	Path    string
	Summary *cert.CertSummary
	Err     error
}

// ContentDetailsMsg carries the full cert text for the details pane.
type ContentDetailsMsg struct {
	Path    string
	Details *cert.CertDetails
	Err     error
}

// StatusMsg sets a temporary status message in the status bar.
type StatusMsg struct {
	Text  string
	IsErr bool
}

// ActionResultMsg is sent when an action completes.
type ActionResultMsg struct {
	Message string
	IsErr   bool
	Details string
}

// RefreshFilesMsg tells the file pane to refresh its listing.
type RefreshFilesMsg struct{}

// AutoKeyMatchMsg carries the result of opportunistic key matching.
type AutoKeyMatchMsg struct {
	CertPath string
	KeyPath  string // empty if no match found
	Err      error
}
