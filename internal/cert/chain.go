package cert

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// ChainEntry describes a single certificate in an ordered chain.
type ChainEntry struct {
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	IsCA         bool   `json:"is_ca"`
	IsSelfSigned bool   `json:"is_self_signed"`
}

// ChainResult holds the ordered chain and any warnings.
type ChainResult struct {
	Certs    []ChainEntry `json:"certs"`
	Warnings []string     `json:"warnings,omitempty"`
}

// OrderChain reads a PEM bundle and returns the certificates ordered from
// leaf → intermediate(s) → root, along with the re-encoded ordered PEM.
func OrderChain(path string) (*ChainResult, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return OrderChainFromPEM(data)
}

// OrderChainFromPEM orders certificates from PEM bytes.
func OrderChainFromPEM(data []byte) (*ChainResult, []byte, error) {
	certs, blocks, err := parsePEMCerts(data)
	if err != nil {
		return nil, nil, err
	}
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no certificates found in PEM data")
	}

	ordered, warnings := orderCerts(certs, blocks)

	result := &ChainResult{
		Warnings: warnings,
	}
	var pemBuf bytes.Buffer
	for _, idx := range ordered {
		c := certs[idx]
		result.Certs = append(result.Certs, ChainEntry{
			Subject:      c.Subject.String(),
			Issuer:       c.Issuer.String(),
			IsCA:         c.IsCA,
			IsSelfSigned: c.Subject.String() == c.Issuer.String(),
		})
		if err := pem.Encode(&pemBuf, blocks[idx]); err != nil {
			return nil, nil, fmt.Errorf("encode PEM: %w", err)
		}
	}

	return result, pemBuf.Bytes(), nil
}

// parsePEMCerts decodes all CERTIFICATE blocks from PEM data.
func parsePEMCerts(data []byte) ([]*x509.Certificate, []*pem.Block, error) {
	var certs []*x509.Certificate
	var blocks []*pem.Block
	rest := data
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = r
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, c)
		blocks = append(blocks, block)
	}
	return certs, blocks, nil
}

// orderCerts returns indices into certs in leaf→intermediate→root order.
func orderCerts(certs []*x509.Certificate, blocks []*pem.Block) ([]int, []string) {
	_ = blocks // kept for signature consistency
	n := len(certs)
	if n <= 1 {
		indices := make([]int, n)
		for i := range indices {
			indices[i] = i
		}
		return indices, nil
	}

	var warnings []string

	// Build a map from SubjectKeyId to index for chain walking.
	skiMap := make(map[string]int)
	for i, c := range certs {
		if len(c.SubjectKeyId) > 0 {
			skiMap[string(c.SubjectKeyId)] = i
		}
	}

	// Build a map from Subject DN to index as fallback.
	subjectMap := make(map[string]int)
	for i, c := range certs {
		subjectMap[c.Subject.String()] = i
	}

	// Find the leaf: a cert that is not used as the issuer of any other cert.
	isIssuer := make(map[int]bool)
	for _, c := range certs {
		// Try AKI → SKI match first.
		if len(c.AuthorityKeyId) > 0 {
			if idx, ok := skiMap[string(c.AuthorityKeyId)]; ok {
				isIssuer[idx] = true
				continue
			}
		}
		// Fallback: Issuer DN → Subject DN.
		if idx, ok := subjectMap[c.Issuer.String()]; ok {
			isIssuer[idx] = true
		}
	}

	leaf := -1
	for i, c := range certs {
		// Self-signed certs are their own issuer; prefer non-self-signed as leaf.
		selfSigned := c.Subject.String() == c.Issuer.String()
		if !isIssuer[i] || (selfSigned && n == 1) {
			// This cert is not the issuer of another cert — candidate leaf.
			if !selfSigned {
				leaf = i
				break
			}
		}
	}
	// If no non-self-signed leaf found, pick the first non-CA cert.
	if leaf == -1 {
		for i, c := range certs {
			if !c.IsCA {
				leaf = i
				break
			}
		}
	}
	// Last resort: pick the first cert.
	if leaf == -1 {
		leaf = 0
	}

	// Walk the chain from leaf to root.
	ordered := []int{leaf}
	visited := map[int]bool{leaf: true}
	current := certs[leaf]

	for len(ordered) < n {
		next := -1
		// Try AKI → SKI.
		if len(current.AuthorityKeyId) > 0 {
			if idx, ok := skiMap[string(current.AuthorityKeyId)]; ok && !visited[idx] {
				next = idx
			}
		}
		// Fallback: Issuer DN → Subject DN.
		if next == -1 {
			if idx, ok := subjectMap[current.Issuer.String()]; ok && !visited[idx] {
				next = idx
			}
		}
		if next == -1 {
			break
		}
		ordered = append(ordered, next)
		visited[next] = true
		current = certs[next]
	}

	// Append any orphan certs not reachable from the leaf.
	if len(ordered) < n {
		var orphans []int
		for i := range certs {
			if !visited[i] {
				orphans = append(orphans, i)
			}
		}
		if len(orphans) > 0 {
			warnings = append(warnings, fmt.Sprintf("%d certificate(s) not reachable from leaf (broken chain)", len(orphans)))
			ordered = append(ordered, orphans...)
		}
	}

	return ordered, warnings
}
