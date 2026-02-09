package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type outputOptions struct {
	color   bool
	unicode bool
	quiet   bool
}

var (
	outStdout io.Writer = os.Stdout
	outStderr io.Writer = os.Stderr
	outOpt              = outputOptions{color: true, unicode: true}
)

func setOutputOptions(stdout, stderr io.Writer, opt outputOptions) {
	if stdout != nil {
		outStdout = stdout
	}
	if stderr != nil {
		outStderr = stderr
	}
	outOpt = opt
}

func colorSeq(s string) string {
	if !outOpt.color {
		return ""
	}
	return s
}

func sym(unicode, ascii string) string {
	if outOpt.unicode {
		return unicode
	}
	return ascii
}

func info(msg string) {
	if outOpt.quiet {
		return
	}
	fmt.Fprintf(outStdout, "%si%s  %s\n", colorSeq("\033[0;34m"), colorSeq("\033[0m"), msg)
}

func success(msg string) {
	if outOpt.quiet {
		return
	}
	g := sym("✓", "OK")
	fmt.Fprintf(outStdout, "%s%s%s  %s\n", colorSeq("\033[0;32m"), g, colorSeq("\033[0m"), msg)
}

func warn(msg string) {
	if outOpt.quiet {
		return
	}
	g := sym("!", "WARN")
	fmt.Fprintf(outStdout, "%s%s%s  %s\n", colorSeq("\033[0;33m"), g, colorSeq("\033[0m"), msg)
}

func errMsg(msg string) {
	g := sym("x", "ERR")
	fmt.Fprintf(outStderr, "%s%s%s  %s\n", colorSeq("\033[0;31m"), g, colorSeq("\033[0m"), msg)
}

func step(msg string) {
	if outOpt.quiet {
		return
	}
	g := sym("→", ">")
	fmt.Fprintf(outStdout, "%s%s%s  %s\n", colorSeq("\033[0;90m"), g, colorSeq("\033[0m"), msg)
}

func kv(key, value string) {
	key = strings.TrimSpace(key)
	if key == "" {
		fmt.Fprintf(outStdout, "  %s\n", value)
		return
	}
	fmt.Fprintf(outStdout, "  %s%s:%s %s\n", colorSeq("\033[1m"), key, colorSeq("\033[0m"), value)
}
