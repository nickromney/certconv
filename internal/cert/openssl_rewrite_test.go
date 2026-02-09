package cert

import (
	"strings"
	"testing"
)

func TestRewriteArgsWithTempSecretFiles_RewritesFDArgs(t *testing.T) {
	args := []string{"pkcs12", "-passin", fdArg(0), "-passout", fdArg(1)}
	rewritten, cleanup, err := rewriteArgsWithTempSecretFiles(args, []ExtraFile{
		{Data: []byte("a")},
		{Data: []byte("b")},
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer cleanup()

	joined := strings.Join(rewritten, " ")
	if strings.Contains(joined, "fd:3") || strings.Contains(joined, "fd:4") {
		t.Fatalf("expected fd args rewritten, got: %q", joined)
	}
	if !strings.Contains(joined, "-passin file:") || !strings.Contains(joined, "-passout file:") {
		t.Fatalf("expected file: args present, got: %q", joined)
	}
}

