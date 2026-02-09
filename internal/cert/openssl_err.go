package cert

import (
	"errors"
	"strings"
)

// preferStderr returns stderr as the error when available. This avoids surfacing
// unhelpful "exit status N" messages to end users.
func preferStderr(err error, stderr []byte) error {
	msg := strings.TrimSpace(string(stderr))
	if msg != "" {
		return errors.New(msg)
	}
	return err
}
