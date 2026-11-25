package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func setFailpoint(t *testing.T, f func(string) error) {
	t.Helper()
	old := auditFailpoint
	auditFailpoint = f
	t.Cleanup(func() { auditFailpoint = old })
}

func testAuditConfig(t *testing.T) *auditConfig {
	t.Helper()
	return &auditConfig{
		LogPath: filepath.Join(t.TempDir(), "acc.audit.jsonl"),
		Policy:  policyBestEffort,
		Timeout: 2 * time.Second,
	}
}

// withSudoGlobals points the package flags/config at a one-entry config.
func withSudoGlobals(t *testing.T, state string, noReuse bool) {
	t.Helper()
	oldCfg, oldSudo, oldNR, oldState, oldTTL, oldLocal := gCfg.Local, *SudoPipe, *NoReuse, *State, *MinTTL, gCfg.Local
	t.Cleanup(func() {
		gCfg.Local, *SudoPipe, *NoReuse, *State, *MinTTL = oldCfg, oldSudo, oldNR, oldState, oldTTL
		_ = oldLocal
	})
	gCfg.Local = []ACConfigItem{{Name: "/myserver:phil", Username: "phil", Password: canaryPW, Secret: testSecret, Realm: "myserver"}}
	*SudoPipe, *NoReuse, *State, *MinTTL = "myserver", noReuse, state, 0
}

func TestUnit_EmittedAppendFailureWithholdsCredentials(t *testing.T) {
	ac := testAuditConfig(t)
	withSudoGlobals(t, "", false)
	var calls int32
	setFailpoint(t, func(name string) error {
		if name == "append_write" && atomic.AddInt32(&calls, 1) == 2 { // the `emitted` append
			return errors.New("injected")
		}
		return nil
	})
	out, fail := sudoPipe(ac)
	if fail == nil || fail.code != 1 || out != nil {
		t.Fatalf("expected failure with no credential bytes, got out=%d fail=%v", len(out), fail)
	}
	if strings.Contains(fail.msg, canaryPW) {
		t.Errorf("failure message leaks the password")
	}
	l := newAuditLogger(ac)
	s, err := l.status()
	if err != nil {
		t.Fatal(err)
	}
	// Honest record: the request exists, with no invented outcome.
	if s.Records != 1 || s.UnfinishedRequests != 1 {
		t.Errorf("status = %+v, want 1 record and 1 unfinished request", s)
	}
}

func TestUnit_RequestedAppendFailureDoesNotBurnNoReuse(t *testing.T) {
	ac := testAuditConfig(t)
	state := filepath.Join(t.TempDir(), "state.json")
	withSudoGlobals(t, state, true)
	setFailpoint(t, func(name string) error {
		if name == "append_write" {
			return errors.New("injected")
		}
		return nil
	})
	if out, fail := sudoPipe(ac); fail == nil || out != nil {
		t.Fatalf("expected failure")
	}
	if _, err := os.Stat(state); err == nil {
		t.Errorf("no-reuse window was burned before the requested record was durable")
	}
}

func TestUnit_CursorWriteFailureFailsClosed(t *testing.T) {
	ac := testAuditConfig(t)
	withSudoGlobals(t, "", false)
	setFailpoint(t, func(name string) error {
		if name == "cursor_write" {
			return errors.New("injected")
		}
		return nil
	})
	if out, fail := sudoPipe(ac); fail == nil || out != nil {
		t.Fatalf("cursor write failure must withhold credentials")
	}
}

func TestUnit_CrashBetweenAcceptAndCursor(t *testing.T) {
	ac := testAuditConfig(t)
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Idempotency-Key"))
	}))
	defer srv.Close()
	ac.SinkURL = srv.URL
	l := newAuditLogger(ac)
	op := newAuditOp(auditKindSudo, ac)
	r1, r2 := op.rec(phaseRequested, "requested", ""), op.rec(phaseEmitted, "credentials_emitted", "")
	for _, r := range []auditRecord{r1, r2} {
		if err := l.append(r); err != nil {
			t.Fatal(err)
		}
	}

	// The sink accepts record 1 but the cursor write "crashes".
	setFailpoint(t, func(name string) error {
		if name == "cursor_write" {
			return errors.New("injected crash")
		}
		return nil
	})
	if _, err := l.ship(srv.Client(), false, ""); err == nil {
		t.Fatalf("expected the cursor failure to surface")
	}
	auditFailpoint = func(string) error { return nil }
	if s, _ := l.status(); s.Pending != 2 {
		t.Fatalf("pending = %d, want 2 (accepted-but-uncursored record stays pending)", s.Pending)
	}
	// Retry resends record 1 (duplicate, same idempotency key) then record 2: none skipped.
	res, err := l.ship(srv.Client(), false, "")
	if err != nil || !res.Reached || res.Pending != 0 {
		t.Fatalf("retry: %+v %v", res, err)
	}
	want := []string{r1.RecordID, r1.RecordID, r2.RecordID}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("deliveries = %v, want %v", got, want)
	}
}

func TestUnit_RotateFailureInjectionPreservesLog(t *testing.T) {
	for _, fp := range []string{"rotate_link", "rotate_fresh", "rotate_cursor_stage", "rotate_swap", "rotate_cursor_commit"} {
		t.Run(fp, func(t *testing.T) {
			ac := testAuditConfig(t)
			l := newAuditLogger(ac)
			op := newAuditOp(auditKindSudo, ac)
			for _, r := range []auditRecord{op.rec(phaseRequested, "requested", ""), op.rec(phaseEmitted, "credentials_emitted", "")} {
				if err := l.append(r); err != nil {
					t.Fatal(err)
				}
			}
			logBefore, curBefore := readFile(t, ac.LogPath), readFile(t, ac.cursorPath())
			setFailpoint(t, func(name string) error {
				if name == fp {
					return errors.New("injected")
				}
				return nil
			})
			if _, err := l.rotate(); err == nil {
				t.Fatalf("rotate should fail")
			}
			if readFile(t, ac.LogPath) != logBefore || readFile(t, ac.cursorPath()) != curBefore {
				t.Errorf("original log/cursor changed after failed rotation")
			}
			var names []string
			ents, _ := os.ReadDir(filepath.Dir(ac.LogPath))
			for _, e := range ents {
				names = append(names, e.Name())
			}
			sort.Strings(names)
			want := []string{"acc.audit.jsonl", "acc.audit.jsonl.delivery.json", "acc.audit.jsonl.lock"}
			if strings.Join(names, ",") != strings.Join(want, ",") {
				t.Errorf("leftover files after failed rotation: %v", names)
			}
			auditFailpoint = func(string) error { return nil }
			if res, err := l.rotate(); err != nil || !res.Rotated {
				t.Errorf("rotate should succeed once the fault is gone: %v", err)
			}
		})
	}
}

func TestUnit_RotationCrashRecovery(t *testing.T) {
	// Fresh (empty) log with a stale non-zero cursor is the state a crash
	// between the log swap and the cursor swap would leave; it must recover.
	ac := testAuditConfig(t)
	if err := os.WriteFile(ac.LogPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ac.cursorPath(), []byte(`{"offset":500}`), 0600); err != nil {
		t.Fatal(err)
	}
	l := newAuditLogger(ac)
	op := newAuditOp(auditKindSudo, ac)
	if err := l.append(op.rec(phaseRequested, "requested", "")); err != nil {
		t.Fatalf("append after interrupted rotation: %v", err)
	}
}

func TestUnit_HTTPSReceiverContract(t *testing.T) {
	var gotHdr http.Header
	var proto string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHdr = r.Header.Clone()
		proto = r.URL.Scheme + "|" + r.Method
		w.WriteHeader(204) // any 2xx is acceptance
	}))
	defer srv.Close()
	ac := testAuditConfig(t)
	ac.SinkURL = srv.URL
	if err := validateSinkURL(ac.SinkURL); err != nil {
		t.Fatalf("https sink rejected: %v", err)
	}
	l := newAuditLogger(ac)
	op := newAuditOp(auditKindSudo, ac)
	rec := op.rec(phaseRequested, "requested", "")
	if err := l.append(rec); err != nil {
		t.Fatal(err)
	}
	res, err := l.ship(srv.Client(), true, rec.RecordID)
	if err != nil || !res.Reached {
		t.Fatalf("ship over TLS: %+v %v", res, err)
	}
	if gotHdr.Get("Idempotency-Key") != rec.RecordID || gotHdr.Get("X-Acc-Audit-Record-Id") != rec.RecordID {
		t.Errorf("headers: %v", gotHdr)
	}
	if proto != "|POST" {
		t.Errorf("method = %q", proto)
	}
}

func TestUnit_ValidateSinkURL(t *testing.T) {
	good := []string{"https://audit.example.com/acc", "http://127.0.0.1:8080/x", "http://localhost/x", "http://[::1]:9/x"}
	bad := []string{"http://audit.example.com/x", "https://u:p@audit.example.com/", "https://a.example.com/?t=1", "https://a.example.com/#f", "ftp://a/", "", "audit"}
	for _, u := range good {
		if err := validateSinkURL(u); err != nil {
			t.Errorf("%q rejected: %v", u, err)
		}
	}
	for _, u := range bad {
		if err := validateSinkURL(u); err == nil {
			t.Errorf("%q accepted", u)
		} else if strings.Contains(err.Error(), "p@") {
			t.Errorf("error echoes credentials: %v", err)
		}
	}
}

func TestUnit_AppendRefusesLeftoverPartialWrite(t *testing.T) {
	ac := testAuditConfig(t)
	l := newAuditLogger(ac)
	op := newAuditOp(auditKindSudo, ac)
	if err := l.append(op.rec(phaseRequested, "requested", "")); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(ac.LogPath, os.O_APPEND|os.O_WRONLY, 0600)
	_, _ = f.WriteString(`{"schema_version":1,"record_id":"x"`) // torn write
	_ = f.Close()
	if err := l.append(op.rec(phaseEmitted, "credentials_emitted", "")); err == nil || !strings.Contains(err.Error(), "partial") {
		t.Errorf("append onto a torn log must fail loudly, got %v", err)
	}
	if _, err := l.status(); err == nil {
		t.Errorf("status must report the corrupt log")
	}
}
