//go:build windows

package upgrade

import (
	"errors"
	"fmt"
	"os"
)

// backupPath returns the path the running binary is renamed aside to. Windows
// refuses to delete or overwrite the image of a running executable, but it
// does allow renaming it; the leftover .old is removed by the NEXT upgrade
// attempt (the current process keeps the old image alive until exit).
func backupPath(exePath string) string { return exePath + ".old" }

// swapIn installs tmpPath over exePath on Windows: move the running binary
// aside, then move the new one into place, rolling back if the second move
// fails so the previous binary is never left missing.
func swapIn(tmpPath, exePath string) error {
	old := backupPath(exePath)
	if err := os.Remove(old); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear stale %s: %w", old, err)
	}
	if err := os.Rename(exePath, old); err != nil {
		return fmt.Errorf("move running binary aside to %s: %w", old, err)
	}
	if err := os.Rename(tmpPath, exePath); err != nil {
		if rb := os.Rename(old, exePath); rb != nil {
			return fmt.Errorf("install new binary: %v (rollback also failed: %v)", err, rb)
		}
		return fmt.Errorf("install new binary: %w (previous binary restored)", err)
	}
	return nil // old is deliberately left on disk; see backupPath
}
