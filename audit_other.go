//go:build !unix

package main

import (
	"errors"
	"os"
	"time"
)

const oNoFollow = 0

// Audit locking is only implemented on unix; elsewhere audited operations fail
// closed rather than run without a cross-process lock.
func flockExclusive(f *os.File, wait time.Duration) error {
	return errors.New("audit logging requires a unix platform (no cross-process lock available)")
}

func flockRelease(f *os.File) {}
