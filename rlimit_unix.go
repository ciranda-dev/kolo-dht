//go:build unix

package kolodht

import (
	"math"
	"syscall"
)

// softNoFile returns the soft RLIMIT_NOFILE, or -1 if it cannot be read or does not fit an int.
func softNoFile() int {
	var r syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &r); err != nil {
		return -1
	}
	cur := uint64(r.Cur)
	if cur > math.MaxInt32 {
		return -1
	}
	return int(cur)
}
