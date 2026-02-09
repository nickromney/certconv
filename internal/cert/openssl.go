package cert

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type ExtraFile struct {
	// Data is written to the file descriptor before launching openssl. A trailing
	// newline is added if missing, to match typical passphrase file semantics.
	Data []byte
}

// Executor runs openssl commands and returns stdout, stderr, and any error.
type Executor interface {
	Run(ctx context.Context, args ...string) (stdout, stderr []byte, err error)
	RunWithExtraFiles(ctx context.Context, files []ExtraFile, args ...string) (stdout, stderr []byte, err error)
}

// OSExecutor calls openssl via exec.CommandContext.
type OSExecutor struct{}

func (o *OSExecutor) Run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	return o.RunWithExtraFiles(ctx, nil, args...)
}

func (o *OSExecutor) RunWithExtraFiles(ctx context.Context, files []ExtraFile, args ...string) ([]byte, []byte, error) {
	// ExtraFiles (and fd:N passphrases) are Unix-only. For best-effort Windows
	// support, fall back to temp files and rewrite fd:3 -> file:<path>.
	//
	// This isn't as good as FDs (it hits disk), but it keeps the CLI usable when
	// running on Windows and prevents leaking secrets via argv `pass:...`.
	if runtime.GOOS == "windows" && len(files) > 0 {
		rewritten, cleanup, err := rewriteArgsWithTempSecretFiles(args, files)
		if err != nil {
			return nil, nil, err
		}
		defer cleanup()

		cmd := exec.CommandContext(ctx, "openssl", rewritten...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err = cmd.Run()
		return stdout.Bytes(), stderr.Bytes(), err
	}

	cmd := exec.CommandContext(ctx, "openssl", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	var toClose []*os.File
	defer func() {
		for _, f := range toClose {
			_ = f.Close()
		}
	}()

	if len(files) > 0 {
		cmd.ExtraFiles = make([]*os.File, 0, len(files))
		for _, ef := range files {
			r, w, err := os.Pipe()
			if err != nil {
				return nil, nil, err
			}
			toClose = append(toClose, r)

			// Write then close the write end so openssl sees EOF.
			data := ef.Data
			if len(data) == 0 || data[len(data)-1] != '\n' {
				data = append(append([]byte{}, data...), '\n')
			}
			_, _ = w.Write(data)
			_ = w.Close()

			cmd.ExtraFiles = append(cmd.ExtraFiles, r)
		}
	}

	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// Engine wraps an Executor and provides all certificate operations.
type Engine struct {
	exec Executor
}

// NewEngine creates an Engine with the given Executor.
func NewEngine(exec Executor) *Engine {
	return &Engine{exec: exec}
}

// NewDefaultEngine creates an Engine with the real OS executor.
func NewDefaultEngine() *Engine {
	return &Engine{exec: &OSExecutor{}}
}

// run is a convenience helper that runs openssl and returns an error wrapping stderr on failure.
func (e *Engine) run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	stdout, stderr, err := e.exec.Run(ctx, args...)
	if err != nil {
		return stdout, stderr, fmt.Errorf("openssl %s: %w: %s", args[0], err, bytes.TrimSpace(stderr))
	}
	return stdout, stderr, nil
}

func fdArg(extraIndex int) string {
	// exec.Cmd.ExtraFiles are inherited as fd 3,4,5... in order.
	return fmt.Sprintf("fd:%d", 3+extraIndex)
}

func rewriteArgsWithTempSecretFiles(args []string, files []ExtraFile) (rewritten []string, cleanup func(), err error) {
	if len(files) == 0 {
		return append([]string(nil), args...), func() {}, nil
	}

	tmpPaths := make([]string, 0, len(files))
	cleanup = func() {
		for _, p := range tmpPaths {
			_ = os.Remove(p)
		}
	}

	for _, ef := range files {
		f, err := os.CreateTemp("", "certconv-secret-*")
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		path := f.Name()

		data := ef.Data
		if len(data) == 0 || data[len(data)-1] != '\n' {
			data = append(append([]byte{}, data...), '\n')
		}
		if _, err := f.Write(data); err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			cleanup()
			return nil, func() {}, err
		}
		_ = f.Close()

		// Best-effort; may be ignored on Windows but is still useful on WSL.
		_ = os.Chmod(path, 0o600)
		tmpPaths = append(tmpPaths, path)
	}

	rewritten = append([]string(nil), args...)
	for i, p := range tmpPaths {
		want := fdArg(i)
		repl := "file:" + p
		for j := range rewritten {
			// We always pass exact tokens like "fd:3" from fdArg().
			if strings.TrimSpace(rewritten[j]) == want {
				rewritten[j] = repl
			}
		}
	}
	return rewritten, cleanup, nil
}
