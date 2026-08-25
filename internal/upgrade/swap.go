//go:build !windows

package upgrade

import (
	"fmt"
	"os"
	"path/filepath"
)

// swapIn atomically moves the fully written and verified tmpFile over exePath.
// On POSIX systems rename is atomic and safe over a running image — the kernel
// pins the old inode until the process exits.
func swapIn(tmpPath, exePath string) error {
	if err := os.Rename(tmpPath, exePath); err != nil {
		return fmt.Errorf("replace %s: %w", exePath, err)
	}
	// Best effort: flush the directory entry so the new file survives a crash.
	if dir, err := os.Open(filepath.Dir(exePath)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
