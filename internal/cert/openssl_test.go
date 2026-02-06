package cert

import (
	"context"
	"testing"
)

func TestOSExecutor_Version(t *testing.T) {
	exec := &OSExecutor{}
	stdout, _, err := exec.Run(context.Background(), "version")
	if err != nil {
		t.Fatalf("openssl version failed: %v", err)
	}
	if len(stdout) == 0 {
		t.Error("expected openssl version output, got empty")
	}
}

func TestOSExecutor_InvalidCommand(t *testing.T) {
	exec := &OSExecutor{}
	// "openssl <unknown-subcommand>" may exit 0 on some OpenSSL builds, so use an
	// invalid flag on a real subcommand to reliably force a non-zero exit.
	_, _, err := exec.Run(context.Background(), "x509", "-this-flag-should-not-exist")
	if err == nil {
		t.Error("expected error for invalid openssl invocation")
	}
}
