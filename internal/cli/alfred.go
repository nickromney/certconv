package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nickromney/certconv/internal/cert"
	"github.com/spf13/cobra"
)

var errAlfredCancelled = errors.New("alfred action cancelled")

type alfredItem struct {
	UID      string `json:"uid,omitempty"`
	Title    string `json:"title"`
	Subtitle string `json:"subtitle,omitempty"`
	Arg      string `json:"arg,omitempty"`
	Match    string `json:"match,omitempty"`
}

type alfredItemsResponse struct {
	Items []alfredItem `json:"items"`
}

type alfredActionSpec struct {
	ID       string
	Title    string
	Subtitle string
	Keywords string
}

type alfredCatalog struct {
	actions []alfredActionSpec
}

func newAlfredCatalog() alfredCatalog {
	return alfredCatalog{
		actions: []alfredActionSpec{
			{
				ID:       "show-summary",
				Title:    "Show certificate summary",
				Subtitle: "Inspect local certificate metadata without converting anything.",
				Keywords: "show summary inspect read certificate cert pem der pfx p12 details",
			},
			{
				ID:       "show-full",
				Title:    "Show full certificate details",
				Subtitle: "Open the full parsed certificate details in a temporary text preview.",
				Keywords: "show full inspect read certificate text details openssl pem der pfx p12",
			},
			{
				ID:       "pem-cert-to-der",
				Title:    "PEM certificate to DER",
				Subtitle: "Choose a PEM/CRT certificate and save a .der copy.",
				Keywords: "pem der crt certificate x509 convert export",
			},
			{
				ID:       "der-cert-to-pem",
				Title:    "DER certificate to PEM",
				Subtitle: "Choose a DER certificate and save a .pem copy.",
				Keywords: "der pem certificate x509 convert import",
			},
			{
				ID:       "pfx-to-pem",
				Title:    "PFX/P12 to PEM files",
				Subtitle: "Extract certificate, key, and CA bundle from a PFX/P12.",
				Keywords: "pfx p12 pkcs12 pem extract certificate key convert",
			},
			{
				ID:       "pem-cert-key-to-pfx",
				Title:    "PEM cert + key to PFX/P12",
				Subtitle: "Choose a certificate and matching key, then create a .p12.",
				Keywords: "pem key pfx p12 pkcs12 bundle convert export",
			},
			{
				ID:       "p7b-to-pem",
				Title:    "PKCS#7/P7B to PEM files",
				Subtitle: "Extract PEM certificates from a .p7b/.p7c container.",
				Keywords: "p7b p7c pkcs7 pem extract certificates convert",
			},
			{
				ID:       "pem-to-base64",
				Title:    "Binary or PEM file to Base64",
				Subtitle: "Encode a file as raw base64 without line breaks.",
				Keywords: "base64 encode binary pem pfx der convert",
			},
			{
				ID:       "base64-to-binary",
				Title:    "Base64 file to binary",
				Subtitle: "Decode raw base64 content into a binary output file.",
				Keywords: "base64 decode binary der pfx convert",
			},
			{
				ID:       "combine-pem",
				Title:    "Combine PEM cert + key",
				Subtitle: "Create a single combined PEM from a certificate and key.",
				Keywords: "combine pem cert key bundle convert",
			},
		},
	}
}

func (c alfredCatalog) Items(query string) alfredItemsResponse {
	query = strings.TrimSpace(strings.ToLower(query))
	items := make([]alfredItem, 0, len(c.actions))
	for _, action := range c.actions {
		match := strings.ToLower(strings.Join([]string{action.Title, action.Subtitle, action.Keywords, action.ID}, " "))
		if !matchesAlfredQuery(match, query) {
			continue
		}
		items = append(items, alfredItem{
			UID:      action.ID,
			Title:    action.Title,
			Subtitle: action.Subtitle,
			Arg:      action.ID,
			Match:    match,
		})
	}
	return alfredItemsResponse{Items: items}
}

func matchesAlfredQuery(haystack, query string) bool {
	if query == "" {
		return true
	}
	for _, part := range strings.Fields(query) {
		if !strings.Contains(haystack, part) {
			return false
		}
	}
	return true
}

type alfredUI interface {
	ChooseFile(ctx context.Context, prompt string) (string, error)
	ChooseFolder(ctx context.Context, prompt string) (string, error)
	SaveFile(ctx context.Context, prompt, defaultPath string) (string, error)
	PromptSecret(ctx context.Context, prompt string) (string, error)
	Notify(ctx context.Context, title, body string) error
	PreviewText(ctx context.Context, name, text string) error
	Reveal(ctx context.Context, path string) error
}

type alfredOps interface {
	ShowSummary(ctx context.Context, inputPath, password string) (*cert.CertSummary, error)
	ShowDetails(ctx context.Context, inputPath, password string) (*cert.CertDetails, error)
	ToDER(ctx context.Context, inputPath, outputPath string, isKey bool, keyPassword string) error
	FromDER(ctx context.Context, inputPath, outputPath string, isKey bool, keyPassword string) error
	FromPFX(ctx context.Context, inputPath, outputDir, password string) (*cert.FromPFXResult, error)
	ToPFX(ctx context.Context, certPath, keyPath, outputPath, password, caPath, keyPassword string) error
	FromP7B(ctx context.Context, path, outDir string) (*cert.FromP7BResult, error)
	ToBase64(ctx context.Context, inputPath, outputPath string) error
	FromBase64(ctx context.Context, inputPath, outputPath string) error
	CombinePEM(ctx context.Context, certPath, keyPath, outputPath, caPath, keyPassword string) error
}

type alfredRunner struct {
	ops alfredOps
	ui  alfredUI
}

func newAlfredRunner(ops alfredOps, ui alfredUI) *alfredRunner {
	return &alfredRunner{ops: ops, ui: ui}
}

func (r *alfredRunner) Run(ctx context.Context, actionID string) error {
	switch strings.TrimSpace(actionID) {
	case "show-summary":
		input, err := r.ui.ChooseFile(ctx, "Choose a certificate-related file")
		if err != nil {
			return err
		}
		password, err := r.passwordIfNeeded(ctx, input)
		if err != nil {
			return err
		}
		summary, err := r.ops.ShowSummary(ctx, input, password)
		if err != nil {
			return err
		}
		if summary == nil {
			return fmt.Errorf("no summary available for %s", input)
		}
		if err := r.ui.PreviewText(ctx, previewName(input, "summary"), renderSummaryText(summary)); err != nil {
			return err
		}
		return r.ui.Notify(ctx, "Opened certificate summary", filepath.Base(input))

	case "show-full":
		input, err := r.ui.ChooseFile(ctx, "Choose a certificate-related file")
		if err != nil {
			return err
		}
		password, err := r.passwordIfNeeded(ctx, input)
		if err != nil {
			return err
		}
		details, err := r.ops.ShowDetails(ctx, input, password)
		if err != nil {
			return err
		}
		if details == nil {
			return fmt.Errorf("no details available for %s", input)
		}
		if err := r.ui.PreviewText(ctx, previewName(input, "details"), details.RawText); err != nil {
			return err
		}
		return r.ui.Notify(ctx, "Opened certificate details", filepath.Base(input))

	case "pem-cert-to-der":
		input, err := r.ui.ChooseFile(ctx, "Choose a PEM/CRT certificate")
		if err != nil {
			return err
		}
		output, err := r.ui.SaveFile(ctx, "Save DER certificate as", replaceExt(input, ".der"))
		if err != nil {
			return err
		}
		if err := r.ops.ToDER(ctx, input, output, false, ""); err != nil {
			return err
		}
		return r.finish(ctx, output, "Created DER certificate", filepath.Base(output))

	case "der-cert-to-pem":
		input, err := r.ui.ChooseFile(ctx, "Choose a DER certificate")
		if err != nil {
			return err
		}
		output, err := r.ui.SaveFile(ctx, "Save PEM certificate as", replaceExt(input, ".pem"))
		if err != nil {
			return err
		}
		if err := r.ops.FromDER(ctx, input, output, false, ""); err != nil {
			return err
		}
		return r.finish(ctx, output, "Created PEM certificate", filepath.Base(output))

	case "pfx-to-pem":
		input, err := r.ui.ChooseFile(ctx, "Choose a PFX/P12 file")
		if err != nil {
			return err
		}
		password, err := r.ui.PromptSecret(ctx, "Enter the PFX/P12 password (leave blank if empty)")
		if err != nil {
			return err
		}
		parent, err := r.ui.ChooseFolder(ctx, "Choose a parent folder for the extracted PEM files")
		if err != nil {
			return err
		}
		outDir := filepath.Join(parent, extractedDirName(input))
		if _, err := r.ops.FromPFX(ctx, input, outDir, password); err != nil {
			return err
		}
		return r.finish(ctx, outDir, "Extracted PEM files", filepath.Base(outDir))

	case "pem-cert-key-to-pfx":
		certPath, err := r.ui.ChooseFile(ctx, "Choose a PEM certificate")
		if err != nil {
			return err
		}
		keyPath, err := r.ui.ChooseFile(ctx, "Choose the matching PEM private key")
		if err != nil {
			return err
		}
		output, err := r.ui.SaveFile(ctx, "Save PFX/P12 as", replaceExt(certPath, ".p12"))
		if err != nil {
			return err
		}
		password, err := r.ui.PromptSecret(ctx, "Choose an export password for the PFX/P12 (leave blank for none)")
		if err != nil {
			return err
		}
		if err := r.ops.ToPFX(ctx, certPath, keyPath, output, password, "", ""); err != nil {
			return err
		}
		return r.finish(ctx, output, "Created PFX/P12 bundle", filepath.Base(output))

	case "p7b-to-pem":
		input, err := r.ui.ChooseFile(ctx, "Choose a PKCS#7/P7B file")
		if err != nil {
			return err
		}
		parent, err := r.ui.ChooseFolder(ctx, "Choose a parent folder for the extracted PEM files")
		if err != nil {
			return err
		}
		outDir := filepath.Join(parent, extractedDirName(input))
		if _, err := r.ops.FromP7B(ctx, input, outDir); err != nil {
			return err
		}
		return r.finish(ctx, outDir, "Extracted PEM certificates", filepath.Base(outDir))

	case "pem-to-base64":
		input, err := r.ui.ChooseFile(ctx, "Choose a file to encode as raw base64")
		if err != nil {
			return err
		}
		output, err := r.ui.SaveFile(ctx, "Save base64 output as", replaceExt(input, ".b64"))
		if err != nil {
			return err
		}
		if err := r.ops.ToBase64(ctx, input, output); err != nil {
			return err
		}
		return r.finish(ctx, output, "Created base64 file", filepath.Base(output))

	case "base64-to-binary":
		input, err := r.ui.ChooseFile(ctx, "Choose a raw base64 file")
		if err != nil {
			return err
		}
		output, err := r.ui.SaveFile(ctx, "Save decoded binary as", defaultBinaryOutputPath(input))
		if err != nil {
			return err
		}
		if err := r.ops.FromBase64(ctx, input, output); err != nil {
			return err
		}
		return r.finish(ctx, output, "Created decoded binary", filepath.Base(output))

	case "combine-pem":
		certPath, err := r.ui.ChooseFile(ctx, "Choose a PEM certificate")
		if err != nil {
			return err
		}
		keyPath, err := r.ui.ChooseFile(ctx, "Choose the matching PEM private key")
		if err != nil {
			return err
		}
		output, err := r.ui.SaveFile(ctx, "Save combined PEM as", combineOutputPath(certPath))
		if err != nil {
			return err
		}
		if err := r.ops.CombinePEM(ctx, certPath, keyPath, output, "", ""); err != nil {
			return err
		}
		return r.finish(ctx, output, "Created combined PEM", filepath.Base(output))
	}
	return fmt.Errorf("unknown Alfred action: %s", actionID)
}

func (r *alfredRunner) passwordIfNeeded(ctx context.Context, input string) (string, error) {
	if !looksLikePFXPath(input) {
		return "", nil
	}
	return r.ui.PromptSecret(ctx, "Enter the PFX/P12 password (leave blank if empty)")
}

func (r *alfredRunner) finish(ctx context.Context, revealPath, title, body string) error {
	if err := r.ui.Reveal(ctx, revealPath); err != nil {
		return err
	}
	return r.ui.Notify(ctx, title, body)
}

func replaceExt(path, ext string) string {
	dir := filepath.Dir(path)
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	return filepath.Join(dir, name+ext)
}

func combineOutputPath(certPath string) string {
	dir := filepath.Dir(certPath)
	name := strings.TrimSuffix(filepath.Base(certPath), filepath.Ext(certPath))
	return filepath.Join(dir, name+"-combined.pem")
}

func defaultBinaryOutputPath(input string) string {
	ext := strings.ToLower(filepath.Ext(input))
	if ext == ".b64" || ext == ".base64" {
		base := strings.TrimSuffix(filepath.Base(input), filepath.Ext(input))
		return filepath.Join(filepath.Dir(input), base+".bin")
	}
	return replaceExt(input, ".bin")
}

func extractedDirName(input string) string {
	base := strings.TrimSuffix(filepath.Base(input), filepath.Ext(input))
	return base + "-extracted"
}

func previewName(input, suffix string) string {
	base := strings.TrimSuffix(filepath.Base(input), filepath.Ext(input))
	base = strings.TrimSpace(base)
	if base == "" {
		base = "certconv"
	}
	return base + "-" + suffix + ".txt"
}

func renderSummaryText(s *cert.CertSummary) string {
	var b strings.Builder
	if s == nil {
		return ""
	}
	fmt.Fprintf(&b, "File: %s\n", s.File)
	fmt.Fprintf(&b, "Type: %s\n\n", s.FileType)
	if s.FileType == cert.FileTypeKey {
		if s.KeyType != "" {
			fmt.Fprintf(&b, "Key Type: %s\n", s.KeyType)
		}
		return b.String()
	}
	if s.Subject != "" {
		fmt.Fprintf(&b, "Subject: %s\n", s.Subject)
	}
	if s.Issuer != "" {
		fmt.Fprintf(&b, "Issuer: %s\n", s.Issuer)
	}
	if s.NotBefore != "" {
		fmt.Fprintf(&b, "Not Before: %s\n", s.NotBefore)
	}
	if s.NotAfter != "" {
		fmt.Fprintf(&b, "Not After: %s\n", s.NotAfter)
	}
	if s.Serial != "" {
		fmt.Fprintf(&b, "Serial: %s\n", s.Serial)
	}
	if s.PublicKeyInfo != "" {
		fmt.Fprintf(&b, "Public Key: %s\n", s.PublicKeyInfo)
	} else if s.PublicKeyAlgorithm != "" {
		fmt.Fprintf(&b, "Public Key: %s\n", s.PublicKeyAlgorithm)
	}
	if s.SignatureAlgorithm != "" {
		fmt.Fprintf(&b, "Signature: %s\n", s.SignatureAlgorithm)
	}
	if s.Fingerprint != "" {
		fmt.Fprintf(&b, "Fingerprint: %s\n", s.Fingerprint)
	}
	return b.String()
}

func looksLikePFXPath(path string) bool {
	ft, err := cert.DetectType(path)
	if err == nil {
		return ft == cert.FileTypePFX
	}
	ext := strings.ToLower(filepath.Ext(strings.TrimSpace(path)))
	return ext == ".pfx" || ext == ".p12"
}

type macOSAlfredUI struct{}

func newMacOSAlfredUI() alfredUI {
	return macOSAlfredUI{}
}

func (macOSAlfredUI) ChooseFile(ctx context.Context, prompt string) (string, error) {
	return runAppleScript(ctx,
		fmt.Sprintf(`POSIX path of (choose file with prompt %s)`, appleScriptString(prompt)),
	)
}

func (macOSAlfredUI) ChooseFolder(ctx context.Context, prompt string) (string, error) {
	return runAppleScript(ctx,
		fmt.Sprintf(`POSIX path of (choose folder with prompt %s)`, appleScriptString(prompt)),
	)
}

func (macOSAlfredUI) SaveFile(ctx context.Context, prompt, defaultPath string) (string, error) {
	dir := filepath.Dir(defaultPath)
	base := filepath.Base(defaultPath)
	return runAppleScript(ctx,
		fmt.Sprintf(`set targetFolder to POSIX file %s as alias`, appleScriptString(dir)),
		fmt.Sprintf(`set targetName to %s`, appleScriptString(base)),
		fmt.Sprintf(`POSIX path of (choose file name with prompt %s default location targetFolder default name targetName)`, appleScriptString(prompt)),
	)
}

func (macOSAlfredUI) PromptSecret(ctx context.Context, prompt string) (string, error) {
	return runAppleScript(ctx,
		fmt.Sprintf(`text returned of (display dialog %s default answer "" with hidden answer buttons {"Cancel", "Continue"} default button "Continue")`, appleScriptString(prompt)),
	)
}

func (macOSAlfredUI) Notify(ctx context.Context, title, body string) error {
	_, err := runAppleScript(ctx,
		fmt.Sprintf(`display notification %s with title %s`, appleScriptString(body), appleScriptString(title)),
	)
	return err
}

func (macOSAlfredUI) PreviewText(ctx context.Context, name, text string) error {
	dir, err := os.MkdirTemp("", "certconv-alfred-*")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, filepath.Base(name))
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return err
	}
	return exec.CommandContext(ctx, "open", "-a", "TextEdit", path).Run()
}

func (macOSAlfredUI) Reveal(ctx context.Context, path string) error {
	var cmd *exec.Cmd
	info, err := os.Stat(path)
	if err == nil && info.IsDir() {
		cmd = exec.CommandContext(ctx, "open", path)
	} else {
		cmd = exec.CommandContext(ctx, "open", "-R", path)
	}
	return cmd.Run()
}

func runAppleScript(ctx context.Context, lines ...string) (string, error) {
	args := make([]string, 0, len(lines)*2)
	for _, line := range lines {
		args = append(args, "-e", line)
	}
	cmd := exec.CommandContext(ctx, "osascript", args...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if strings.Contains(strings.ToLower(text), "user canceled") {
			return "", errAlfredCancelled
		}
		if text == "" {
			text = err.Error()
		}
		return "", errors.New(text)
	}
	return text, nil
}

func appleScriptString(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + replacer.Replace(value) + `"`
}

func buildAlfredCommand(engine *cert.Engine) *cobra.Command {
	cmd := &cobra.Command{
		Use:    "alfred",
		Short:  "Support the bundled Alfred workflow",
		Hidden: true,
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "items [query]",
		Short: "Emit Alfred Script Filter items",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			query := ""
			if len(args) == 1 {
				query = args[0]
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetEscapeHTML(false)
			return enc.Encode(newAlfredCatalog().Items(query))
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "run ACTION_ID",
		Short: "Run an Alfred workflow action",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if runtime.GOOS != "darwin" {
				return &ExitError{Code: 2, Msg: "certconv alfred run is only available on macOS"}
			}
			err := newAlfredRunner(newAlfredEngineOps(engine), newMacOSAlfredUI()).Run(cmd.Context(), args[0])
			if errors.Is(err, errAlfredCancelled) {
				return nil
			}
			return err
		},
	})

	return cmd
}

type alfredEngineOps struct {
	engine *cert.Engine
}

func newAlfredEngineOps(engine *cert.Engine) alfredOps {
	return &alfredEngineOps{engine: engine}
}

func (o *alfredEngineOps) ShowSummary(ctx context.Context, inputPath, password string) (*cert.CertSummary, error) {
	if s, err := fastSummary(inputPath, password); err == nil && s != nil {
		return s, nil
	}
	return o.engine.Summary(ctx, inputPath, password)
}

func (o *alfredEngineOps) ShowDetails(ctx context.Context, inputPath, password string) (*cert.CertDetails, error) {
	return o.engine.Details(ctx, inputPath, password)
}

func (o *alfredEngineOps) ToDER(ctx context.Context, inputPath, outputPath string, isKey bool, keyPassword string) error {
	return o.engine.ToDER(ctx, inputPath, outputPath, isKey, keyPassword)
}

func (o *alfredEngineOps) FromDER(ctx context.Context, inputPath, outputPath string, isKey bool, keyPassword string) error {
	return o.engine.FromDER(ctx, inputPath, outputPath, isKey, keyPassword)
}

func (o *alfredEngineOps) FromPFX(ctx context.Context, inputPath, outputDir, password string) (*cert.FromPFXResult, error) {
	return o.engine.FromPFX(ctx, inputPath, outputDir, password)
}

func (o *alfredEngineOps) ToPFX(ctx context.Context, certPath, keyPath, outputPath, password, caPath, keyPassword string) error {
	return o.engine.ToPFX(ctx, certPath, keyPath, outputPath, password, caPath, keyPassword)
}

func (o *alfredEngineOps) FromP7B(ctx context.Context, path, outDir string) (*cert.FromP7BResult, error) {
	return o.engine.FromP7B(ctx, path, outDir)
}

func (o *alfredEngineOps) ToBase64(ctx context.Context, inputPath, outputPath string) error {
	return o.engine.ToBase64(ctx, inputPath, outputPath)
}

func (o *alfredEngineOps) FromBase64(ctx context.Context, inputPath, outputPath string) error {
	return o.engine.FromBase64(ctx, inputPath, outputPath)
}

func (o *alfredEngineOps) CombinePEM(ctx context.Context, certPath, keyPath, outputPath, caPath, keyPassword string) error {
	return o.engine.CombinePEM(ctx, certPath, keyPath, outputPath, caPath, keyPassword)
}
