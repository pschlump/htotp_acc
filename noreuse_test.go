package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeClock is an injectable now/sleep pair: sleeping advances the fake time.
type fakeClock struct {
	t time.Time
}

func (f *fakeClock) now() time.Time        { return f.t }
func (f *fakeClock) sleep(d time.Duration) { f.t = f.t.Add(d) }

// atWindow returns the time `elapsed` seconds into TOTP window w.
func atWindow(w int64, elapsed int64) time.Time {
	return time.Unix(w*totpWindowSeconds+elapsed, 0)
}

func TestDecideNoReuseWindow(t *testing.T) {
	tests := []struct {
		name      string
		last      int64
		now       time.Time
		minTTL    uint
		wantTgt   int64
		wantWait  time.Duration
		wantError string // substring; "" means no error
	}{
		{"no state, mid-window, no min-ttl", 0, atWindow(1000, 10), 0, 1000, 0, ""},
		{"no state, first second of window waits for pad", 0, atWindow(1000, 0), 0, 1000, noReusePadSeconds * time.Second, ""},
		{"no state, ttl below min-ttl advances", 0, atWindow(1000, 25), 10, 1001, 7 * time.Second, ""},
		{"no state, ttl exactly min-ttl stays", 0, atWindow(1000, 20), 10, 1000, 0, ""},
		{"current window already emitted", 1000, atWindow(1000, 10), 0, 1001, 22 * time.Second, ""},
		{"current window emitted and ttl low, emitted wins", 1000, atWindow(1000, 25), 10, 1001, 7 * time.Second, ""},
		{"older window recorded, current is fresh", 999, atWindow(1000, 10), 0, 1000, 0, ""},
		{"clock slightly back waits it out", 1001, atWindow(1000, 10), 0, 1002, 52 * time.Second, ""},
		{"clock way back is an error", 2000, atWindow(1000, 10), 0, 0, 0, "jumped backwards"},
		{"min-ttl too large", 0, atWindow(1000, 10), 29, 0, 0, "too large"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, wait, err := decideNoReuseWindow(tt.last, tt.now, tt.minTTL)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("expected error containing %q, got target=%d wait=%s err=%v", tt.wantError, target, wait, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if target != tt.wantTgt || wait != tt.wantWait {
				t.Errorf("decideNoReuseWindow(%d, %s, %d) = (%d, %s), want (%d, %s)",
					tt.last, tt.now, tt.minTTL, target, wait, tt.wantTgt, tt.wantWait)
			}
		})
	}
}

func TestNoReuseStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acc.state.json")

	st, err := readNoReuseState(path)
	if err != nil {
		t.Fatalf("missing file should be empty state, got error: %v", err)
	}
	if len(st) != 0 {
		t.Fatalf("missing file should be empty state, got %v", st)
	}

	st["/exsms-1:phil"] = 59650230
	if err := writeNoReuseState(path, st); err != nil {
		t.Fatalf("write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("state file mode = %o, want 600", info.Mode().Perm())
	}

	got, err := readNoReuseState(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got["/exsms-1:phil"] != 59650230 {
		t.Errorf("round trip mismatch: %v", got)
	}
}

func TestReadNoReuseStateCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acc.state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readNoReuseState(path); err == nil || !strings.Contains(err.Error(), "unable to parse") {
		t.Fatalf("corrupt state file should be a loud error, got %v", err)
	}
}

func TestGenWithNoReuse_ConsecutiveCallsNeverRepeatWindow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acc.state.json")
	secret := "CKDPKQHM3RWX456R"
	clk := &fakeClock{t: atWindow(1000, 20)} // 10s left on window 1000

	pin1, tl1, err := genWithNoReuse("/srv:bob", secret, 10, path, clk.now, clk.sleep)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if tl1 != 10 {
		t.Errorf("first call tl = %d, want 10 (fresh window, no wait)", tl1)
	}

	// Second call at the same instant: window 1000 is burned, so it must wait
	// for window 1001 and emit a different code.
	pin2, tl2, err := genWithNoReuse("/srv:bob", secret, 10, path, clk.now, clk.sleep)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if clk.t != atWindow(1001, noReusePadSeconds) {
		t.Errorf("second call should have slept to pad-seconds into window 1001, clock at %s", clk.t)
	}
	if tl2 != totpWindowSeconds-noReusePadSeconds {
		t.Errorf("second call tl = %d, want %d", tl2, totpWindowSeconds-noReusePadSeconds)
	}
	if pin1 == pin2 {
		t.Errorf("consecutive calls emitted the same code %q", pin1)
	}

	st, err := readNoReuseState(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if st["/srv:bob"] != 1001 {
		t.Errorf("state = %v, want recorded window 1001", st)
	}

	// A different entry has independent state and still uses the current window.
	if _, _, err := genWithNoReuse("/srv:alice", secret, 10, path, clk.now, clk.sleep); err != nil {
		t.Fatalf("other entry: %v", err)
	}
	st, _ = readNoReuseState(path)
	if st["/srv:alice"] != 1001 {
		t.Errorf("other entry recorded %d, want 1001 (current window at call time)", st["/srv:alice"])
	}
}

func TestGenWithNoReuse_ClockBackwards(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acc.state.json")
	if err := writeNoReuseState(path, noReuseState{"/srv:bob": 5000}); err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: atWindow(1000, 10)}
	if _, _, err := genWithNoReuse("/srv:bob", "CKDPKQHM3RWX456R", 0, path, clk.now, clk.sleep); err == nil ||
		!strings.Contains(err.Error(), "jumped backwards") {
		t.Fatalf("expected clock-backwards error, got %v", err)
	}
}
