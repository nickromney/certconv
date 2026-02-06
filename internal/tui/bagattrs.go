package tui

import "strings"

// stripBagAttributes removes OpenSSL PKCS#12 "Bag Attributes" blocks if present.
// These commonly appear in PEM extracted from PFX/P12 and are usually noise.
func stripBagAttributes(s string) string {
	if !strings.Contains(s, "Bag Attributes") {
		return s
	}

	var out []string
	skipping := false

	for _, line := range strings.Split(s, "\n") {
		trim := strings.TrimSpace(line)

		if trim == "Bag Attributes" {
			skipping = true
			continue
		}

		if skipping {
			// Stop skipping when we hit a PEM boundary.
			if strings.HasPrefix(trim, "-----BEGIN ") {
				skipping = false
				out = append(out, line)
			}
			continue
		}

		out = append(out, line)
	}

	return strings.Join(out, "\n")
}

