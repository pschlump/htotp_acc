//go:build unix

package main

import (
	"os"
	"syscall"
	"time"
)

// oNoFollow makes open(2) fail instead of following a symlink in the final
// path component.
const oNoFollow = syscall.O_NOFOLLOW

// flockExclusive takes an exclusive advisory lock on f, polling until wait
// elapses so a wedged peer cannot stall a TOTP invocation indefinitely.
func flockExclusive(f *os.File, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EINTR {
			return err
		}
		if time.Now().After(deadline) {
			return errAuditLockTimeout
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func flockRelease(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
