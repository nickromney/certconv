package cert

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// Executor runs openssl commands and returns stdout, stderr, and any error.
type Executor interface {
	Run(ctx context.Context, args ...string) (stdout, stderr []byte, err error)
}

// OSExecutor calls openssl via exec.CommandContext.
type OSExecutor struct{}

func (o *OSExecutor) Run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, "openssl", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
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
