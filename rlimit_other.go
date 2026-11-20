//go:build !unix

package kolodht

// softNoFile returns -1: no RLIMIT_NOFILE on this platform.
func softNoFile() int { return -1 }
