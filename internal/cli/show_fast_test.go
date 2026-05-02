package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/nickromney/certconv/internal/cert"
	"github.com/nickromney/certconv/test/testutil"
)

type failExec struct{}

func (failExec) Run(context.Context, ...string) ([]byte, []byte, error) {
	return nil, nil, errors.New("unexpected openssl execution")
}

func (failExec) RunWithExtraFiles(context.Context, []cert.ExtraFile, ...string) ([]byte, []byte, error) {
	return nil, nil, errors.New("unexpected openssl execution")
}

func TestShowCommand_UsesFastPathForValidPEM(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	engine := cert.NewEngine(failExec{})
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"show", pair.CertPath, "--json", "--plain"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	var summary cert.CertSummary
	if err := json.Unmarshal(out.Bytes(), &summary); err != nil {
		t.Fatalf("unmarshal summary: %v", err)
	}
	if summary.FileType != cert.FileTypeCert {
		t.Fatalf("expected file type cert, got %q", summary.FileType)
	}
	if summary.Subject == "" || summary.NotAfter == "" {
		t.Fatalf("expected populated summary, got %+v", summary)
	}
	if errOut.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", errOut.String())
	}
}
