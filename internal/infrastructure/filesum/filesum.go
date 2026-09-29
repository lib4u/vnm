// Package filesum computes the SHA-256 of files, the one digest the agent and
// the installer verify downloads with.
package filesum

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// SHA256 returns the hex SHA-256 of the file at path.
func SHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
