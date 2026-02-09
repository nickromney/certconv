package cli

import "errors"

// ExitError carries an intended process exit code.
//
// Use this for "not really an error" cases like showing help in response to
// non-interactive usage, and for usage errors that should exit 2.
type ExitError struct {
	Code   int
	Silent bool   // if true, main should not print "Error: ..." for this
	Msg    string // optional message (already user-facing)
}

func (e *ExitError) Error() string {
	return e.Msg
}

func ExitCode(err error) (code int, silent bool, ok bool) {
	var ee *ExitError
	if !errors.As(err, &ee) {
		return 0, false, false
	}
	return ee.Code, ee.Silent, true
}
