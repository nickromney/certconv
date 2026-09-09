// Package smoke holds the small PTY smoke set scoped by TESTING.md: drive the
// real binary through a pseudo-terminal with generous assertions. Model-level
// behaviour stays in the package unit tests; these only prove the binary
// starts, draws, and quits cleanly in a real terminal.
package smoke_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/nickromney/certconv/test/testutil"
)

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

// binary builds cmd/certconv once per test run and returns its path.
func binary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "certconv-smoke-*")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "certconv")
		cmd := exec.Command("go", "build", "-o", binPath, "github.com/nickromney/certconv/cmd/certconv")
		cmd.Dir = repoRoot(t)
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = err
			t.Logf("build output: %s", out)
		}
	})
	if buildErr != nil {
		t.Fatalf("build certconv binary: %v", buildErr)
	}
	return binPath
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

func TestSmoke_TUIStartsDrawsAndQuits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PTY smoke tests are Unix-only")
	}

	// Start in a directory holding a real cert/key pair so the browser has
	// content and no first-run overlay captures the quit keys.
	pair := testutil.MakeCertPair(t)
	cmd := exec.Command(binary(t), "tui")
	cmd.Dir = pair.Dir
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 30, Cols: 100})
	if err != nil {
		t.Fatalf("start under pty: %v", err)
	}
	defer func() { _ = ptmx.Close() }()

	// Collect output until the process exits or we stop reading.
	var mu sync.Mutex
	var screen bytes.Buffer
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				mu.Lock()
				screen.Write(buf[:n])
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	// Generous startup window: wait until the TUI has entered the alt screen
	// and drawn a frame that names the app.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		out := screen.String()
		mu.Unlock()
		if strings.Contains(out, "\x1b[?1049h") && strings.Contains(out, "files:") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	mu.Lock()
	if !strings.Contains(screen.String(), "files:") {
		got := screen.Len()
		mu.Unlock()
		t.Fatalf("TUI did not draw a recognisable frame within 10s (%d bytes captured)", got)
	}
	mu.Unlock()

	// Keystroke-driven quit is covered by the model-level tests; keystrokes
	// written to a programmatic PTY are not reliably delivered to Bubble Tea
	// on darwin (verified with the minimal app in testdata/miniapp, which
	// ignores "q" under script(1) and creack/pty alike). The smoke contract
	// here is graceful teardown: SIGINT must end the program promptly and
	// restore the terminal rather than crash.
	time.Sleep(300 * time.Millisecond)
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("send SIGINT: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		// Exit status after SIGINT varies (interrupt is reported as an
		// error by Run); crashing is what we care about.
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		mu.Lock()
		t.Fatalf("binary did not exit within 10s of SIGINT\nlast output:\n%s", tail(screen.String(), 500))
	}

	mu.Lock()
	out := screen.String()
	mu.Unlock()
	if !strings.Contains(out, "\x1b[?1049h") {
		t.Error("expected the alt-screen enter sequence: the TUI never actually started")
	}
	if !strings.Contains(out, "\x1b[?1049l") {
		t.Error("expected the alt-screen exit sequence: the TUI did not restore the terminal on shutdown")
	}
	if strings.Contains(out, "panic:") {
		t.Errorf("TUI panicked during startup/shutdown:\n%s", tail(out, 800))
	}
}

func TestSmoke_NonTTYPrintsHelpAndExits2(t *testing.T) {
	cmd := exec.Command(binary(t))
	cmd.Dir = t.TempDir()
	// Plain pipes: stdin/stdout are not TTYs.
	out, err := cmd.CombinedOutput()

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected exit error (code 2), got: %v\noutput: %s", err, out)
	}
	if code := exitErr.ExitCode(); code != 2 {
		t.Fatalf("exit code = %d, want 2\noutput: %s", code, out)
	}
	if !strings.Contains(string(out), "certconv") || !strings.Contains(strings.ToLower(string(out)), "usage") {
		t.Errorf("expected help text mentioning certconv and usage, got: %s", tail(string(out), 300))
	}
}

func TestSmoke_VersionFlag(t *testing.T) {
	out, err := exec.Command(binary(t), "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("--version failed: %v\noutput: %s", err, out)
	}
	if !strings.HasPrefix(string(out), "certconv ") {
		t.Errorf("version output should start with 'certconv ', got: %s", tail(string(out), 120))
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
