package cert

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/nickromney/certconv/test/testutil"
)

type pfxFailureExecutor struct {
	Executor
	beforeKey func() error
	beforeCA  func() error
}

func (e pfxFailureExecutor) RunWithExtraFiles(ctx context.Context, extra []ExtraFile, args ...string) ([]byte, []byte, error) {
	if slices.Contains(args, "-nocerts") && e.beforeKey != nil {
		if err := e.beforeKey(); err != nil {
			return nil, nil, err
		}
	}
	if slices.Contains(args, "-cacerts") && e.beforeCA != nil {
		if err := e.beforeCA(); err != nil {
			return nil, nil, err
		}
	}
	return e.Executor.RunWithExtraFiles(ctx, extra, args...)
}

func TestFromPFX_FailureAllowsRetry(t *testing.T) {
	for _, failure := range []string{"key extraction", "key publication", "CA publication"} {
		t.Run(failure, func(t *testing.T) {
			pair := testutil.MakeCertPair(t)
			ctx := context.Background()
			engine := NewDefaultEngine()
			pfx := filepath.Join(pair.Dir, "bundle.pfx")
			// Include a CA artefact to exercise failure after both required links.
			if err := engine.ToPFX(ctx, pair.CertPath, pair.KeyPath, pfx, "", pair.CertPath, ""); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(pair.Dir, "out")
			certPath := filepath.Join(out, "bundle.crt")
			keyPath := filepath.Join(out, "bundle.key")
			caPath := filepath.Join(out, "bundle-ca.crt")
			injected := errors.New("injected extraction failure")
			conflict := ""
			exec := pfxFailureExecutor{Executor: &OSExecutor{}}
			switch failure {
			case "key extraction":
				exec.beforeKey = func() error { return injected }
			case "key publication":
				conflict = keyPath
				exec.beforeKey = func() error { return os.WriteFile(conflict, []byte("existing"), 0o600) }
			case "CA publication":
				conflict = caPath
				exec.beforeCA = func() error { return os.WriteFile(conflict, []byte("existing"), 0o600) }
			}
			_, err := NewEngine(exec).FromPFX(ctx, pfx, out, "")
			if err == nil {
				t.Fatal("expected injected failure")
			}
			if conflict == "" && !errors.Is(err, injected) {
				t.Fatalf("unexpected error: %v", err)
			}
			if conflict != "" && !IsOutputExists(err) {
				t.Fatalf("expected output conflict: %v", err)
			}
			for _, path := range []string{certPath, keyPath, caPath} {
				if path == conflict {
					data, err := os.ReadFile(path)
					if err != nil || string(data) != "existing" {
						t.Fatalf("conflicting file changed: %q, %v", data, err)
					}
				} else if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatalf("incomplete output remains: %s (%v)", path, err)
				}
			}
			entries, err := os.ReadDir(out)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.Name()[0] == '.' {
					t.Fatalf("temporary file leaked: %s", entry.Name())
				}
			}
			if conflict != "" {
				if err := os.Remove(conflict); err != nil {
					t.Fatal(err)
				}
			}
			result, err := engine.FromPFX(ctx, pfx, out, "")
			if err != nil {
				t.Fatalf("retry failed: %v", err)
			}
			if err := ValidatePEMCert(result.CertFile); err != nil {
				t.Fatal(err)
			}
			if err := ValidatePEMKey(result.KeyFile); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(result.KeyFile)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("private key mode: %o", info.Mode().Perm())
			}
			_, err = engine.FromPFX(ctx, pfx, out, "")
			if !IsOutputExists(err) {
				t.Fatalf("existing outputs accepted: %v", err)
			}
		})
	}
}
