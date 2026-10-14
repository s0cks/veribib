// Package seal defines the signed statement a bibliography root is sealed
// with, and the digest that the heart image encodes.
//
// Chain of custody, from the picture down to the evidence:
//
//	heart bits  =  sha256("bibroot-heart-v1" 0x00 statement 0x00 signature)
//	signature   =  OpenPGP detached signature over the statement
//	statement   =  root, source-file hash, leaf count, creation time
//	root        =  Merkle root over per-reference records
//	record      =  key, url, fetch time, sha256(pdf)
//
// Because the signature is an input to the heart, nobody without the private
// key can mint a heart that verifies against a manifest.
package seal

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	statementHeader = "bibroot-seal-v1"
	heartDomain     = "bibroot-heart-v1"
)

// Statement is the exact text that gets signed.
func Statement(root, sourceSHA256 string, leaves int, created time.Time) string {
	return fmt.Sprintf("%s\nroot: %s\nsource-sha256: %s\nleaves: %d\ncreated: %s\n",
		statementHeader, root, sourceSHA256, leaves, created.UTC().Format(time.RFC3339))
}

// StatementRoot extracts the root from a statement.
func StatementRoot(statement string) (string, error) {
	lines := strings.Split(statement, "\n")
	if len(lines) == 0 || lines[0] != statementHeader {
		return "", errors.New("not a bibroot seal statement")
	}
	for _, l := range lines[1:] {
		if v, ok := strings.CutPrefix(l, "root: "); ok {
			return v, nil
		}
	}
	return "", errors.New("statement has no root")
}

// Digest is the 32-byte value the heart image encodes. sig is the binary
// signature (nil for an unsigned seal).
func Digest(statement string, sig []byte) string {
	h := sha256.New()
	h.Write([]byte(heartDomain))
	h.Write([]byte{0})
	h.Write([]byte(statement))
	h.Write([]byte{0})
	h.Write(sig)
	return hex.EncodeToString(h.Sum(nil))
}

// Dearmor returns the binary payload of an ASCII-armored PGP block.
func Dearmor(armored string) ([]byte, error) {
	lines := strings.Split(strings.ReplaceAll(armored, "\r\n", "\n"), "\n")
	i := 0
	for i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), "-----BEGIN PGP") {
		i++
	}
	if i == len(lines) {
		return nil, errors.New("no PGP armor found")
	}
	i++
	for i < len(lines) && strings.TrimSpace(lines[i]) != "" { // armor headers
		i++
	}
	i++
	var body strings.Builder
	for ; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		if strings.HasPrefix(l, "=") || strings.HasPrefix(l, "-----END") { // CRC / footer
			break
		}
		body.WriteString(l)
	}
	b, err := base64.StdEncoding.DecodeString(body.String())
	if err != nil {
		return nil, fmt.Errorf("bad armor body: %w", err)
	}
	if len(b) == 0 {
		return nil, errors.New("empty armor body")
	}
	return b, nil
}
