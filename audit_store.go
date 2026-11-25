package main

// Local audit storage: JSONL log, delivery cursor, cross-process lock, status
// and rotation.
//
// Layout (all regular files, mode 0600, symlinks refused):
//
//	<log>                 append-only JSON Lines, never rewritten
//	<log>.lock            flock(2) lock serializing append/flush/rotate
//	<log>.delivery.json   delivery cursor: byte offset of the first unshipped
//	                      record, replaced by temp file + fsync + rename
//
// Without a sink ("local_only") every append advances the cursor to the end of
// the log, so nothing counts as pending for a nonexistent destination. A sink
// configured later therefore ships only records appended after that point.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// auditFailpoint lets tests inject failures at named steps. It is never set
// outside tests.
var auditFailpoint = func(string) error { return nil }

type auditLogger struct {
	cfg *auditConfig
}

func newAuditLogger(cfg *auditConfig) *auditLogger { return &auditLogger{cfg: cfg} }

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

// checkRegular refuses symlinks and non-regular files. With strict set an
// existing file must also have no group/other permission bits.
func checkRegular(path string, strict bool) (exists bool, err error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return true, fmt.Errorf("%s is a symlink; refusing to use it", path)
	}
	if !fi.Mode().IsRegular() {
		return true, fmt.Errorf("%s is not a regular file; refusing to use it", path)
	}
	if strict && fi.Mode().Perm()&0o077 != 0 {
		return true, fmt.Errorf("%s has permissions %04o; it must be 0600", path, fi.Mode().Perm())
	}
	return true, nil
}

// openAuditFile opens (creating 0600 if needed) a regular, non-symlink file.
func openAuditFile(path string, flag int) (*os.File, error) {
	if _, err := checkRegular(path, true); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, flag|oNoFollow, 0o600)
	if err != nil {
		return nil, fmt.Errorf("unable to open %s: %w", path, err)
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%s is not a regular file; refusing to use it", path)
	}
	return f, nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

func ensureAuditDir(logPath string) error {
	dir := filepath.Dir(logPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("unable to create audit directory %s: %w", dir, err)
	}
	return nil
}

// writeFileAtomic writes data to path via a same-directory temp file (0600),
// fsync and rename. Used for the cursor and the event-ID file.
func writeFileAtomic(path string, data []byte, failpoint string) error {
	tmp, err := stageFile(path, data)
	if err != nil {
		return err
	}
	return commitStaged(tmp, path, failpoint)
}

func stageFile(path string, data []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return "", fmt.Errorf("unable to create temp file for %s: %w", path, err)
	}
	tmp := f.Name()
	fail := func(err error) (string, error) {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", fmt.Errorf("unable to write %s: %w", path, err)
	}
	if err := f.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("unable to write %s: %w", path, err)
	}
	return tmp, nil
}

func commitStaged(tmp, path, failpoint string) error {
	if failpoint != "" {
		if err := auditFailpoint(failpoint); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	if _, err := checkRegular(path, false); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("unable to replace %s: %w", path, err)
	}
	syncDir(filepath.Dir(path))
	return nil
}

// ---------------------------------------------------------------------------
// Lock
// ---------------------------------------------------------------------------

type auditLock struct{ f *os.File }

func acquireAuditLock(path string) (*auditLock, error) {
	f, err := openAuditFile(path, os.O_RDWR|os.O_CREATE)
	if err != nil {
		return nil, err
	}
	if err := flockExclusive(f, auditLockWait); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("audit lock %s: %w", path, err)
	}
	return &auditLock{f: f}, nil
}

func (l *auditLock) release() {
	flockRelease(l.f)
	_ = l.f.Close()
}

// ---------------------------------------------------------------------------
// Log scan and cursor
// ---------------------------------------------------------------------------

type logRecord struct {
	start, end int64 // byte range including the trailing newline
	id         string
	eventID    string
	kind       string
	phase      string
	occurredAt string
}

type logScan struct {
	size int64
	recs []logRecord
}

// scanLog validates data as JSON Lines of audit records. A partial trailing
// line or any malformed line is a loud error, never skipped.
func scanLog(data []byte) (*logScan, error) {
	sc := &logScan{size: int64(len(data))}
	var off int64
	for line := 1; off < sc.size; line++ {
		nl := bytes.IndexByte(data[off:], '\n')
		if nl < 0 {
			return nil, errors.New("audit log ends with a partial record (no trailing newline); inspect it before releasing credentials")
		}
		var r struct {
			SchemaVersion int    `json:"schema_version"`
			RecordID      string `json:"record_id"`
			EventID       string `json:"event_id"`
			Kind          string `json:"kind"`
			Phase         string `json:"phase"`
			OccurredAt    string `json:"occurred_at"`
		}
		if err := json.Unmarshal(data[off:off+int64(nl)], &r); err != nil || r.SchemaVersion < 1 || r.RecordID == "" || r.EventID == "" {
			return nil, fmt.Errorf("audit log is corrupt at line %d", line)
		}
		end := off + int64(nl) + 1
		sc.recs = append(sc.recs, logRecord{start: off, end: end, id: r.RecordID, eventID: r.EventID, kind: r.Kind, phase: r.Phase, occurredAt: r.OccurredAt})
		off = end
	}
	return sc, nil
}

type auditCursor struct {
	SchemaVersion  int    `json:"schema_version"`
	Offset         int64  `json:"offset"`
	LastDelivery   string `json:"last_delivery,omitempty"`
	LastDeliveryAt string `json:"last_delivery_at,omitempty"`
}

func readCursor(path string) (auditCursor, error) {
	c := auditCursor{SchemaVersion: 1}
	exists, err := checkRegular(path, true)
	if err != nil {
		return c, err
	}
	if !exists {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("unable to read delivery cursor: %w", err)
	}
	if err := json.Unmarshal(b, &c); err != nil || c.Offset < 0 {
		return auditCursor{}, errors.New("delivery cursor file is corrupt")
	}
	return c, nil
}

func encodeCursor(c auditCursor) []byte {
	c.SchemaVersion = 1
	b, _ := json.Marshal(c)
	return append(b, '\n')
}

func writeCursor(path string, c auditCursor) error {
	return writeFileAtomic(path, encodeCursor(c), "cursor_write")
}

// normalizeCursor validates the cursor against the log. An empty log resets
// the cursor (a crash during rotation, or a fresh log).
func normalizeCursor(c auditCursor, sc *logScan) (auditCursor, error) {
	if sc.size == 0 {
		c.Offset = 0
		return c, nil
	}
	if c.Offset > sc.size {
		return c, errors.New("delivery cursor is beyond the end of the audit log")
	}
	if c.Offset > 0 {
		ok := false
		for _, r := range sc.recs {
			if r.end == c.Offset {
				ok = true
				break
			}
		}
		if !ok {
			return c, errors.New("delivery cursor does not fall on a record boundary")
		}
	}
	return c, nil
}

func (sc *logScan) pendingFrom(offset int64) []logRecord {
	for i, r := range sc.recs {
		if r.start >= offset {
			return sc.recs[i:]
		}
	}
	return nil
}

// auditState is a locked, validated view of the log.
type auditState struct {
	f    *os.File
	data []byte
	scan *logScan
	cur  auditCursor
	lock *auditLock
}

func (s *auditState) close() {
	_ = s.f.Close()
	s.lock.release()
}

// open locks and validates the log. With create unset a missing log yields
// (nil, nil) and nothing is created.
func (l *auditLogger) open(create bool) (*auditState, error) {
	if create {
		if err := ensureAuditDir(l.cfg.LogPath); err != nil {
			return nil, err
		}
	} else {
		exists, err := checkRegular(l.cfg.LogPath, true)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, nil
		}
	}
	lock, err := acquireAuditLock(l.cfg.lockPath())
	if err != nil {
		return nil, err
	}
	flags := os.O_RDWR | os.O_APPEND
	if create {
		flags |= os.O_CREATE
	}
	f, err := openAuditFile(l.cfg.LogPath, flags)
	if err != nil {
		lock.release()
		return nil, err
	}
	st := &auditState{f: f, lock: lock}
	fail := func(err error) (*auditState, error) {
		st.close()
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	st.data = make([]byte, fi.Size())
	if _, err := f.ReadAt(st.data, 0); err != nil && (err != io.EOF || fi.Size() != 0) {
		return fail(fmt.Errorf("unable to read audit log: %w", err))
	}
	if st.scan, err = scanLog(st.data); err != nil {
		return fail(err)
	}
	cur, err := readCursor(l.cfg.cursorPath())
	if err != nil {
		return fail(err)
	}
	if st.cur, err = normalizeCursor(cur, st.scan); err != nil {
		return fail(err)
	}
	return st, nil
}

// ---------------------------------------------------------------------------
// Append
// ---------------------------------------------------------------------------

// append durably adds one record: locked, validated, written in one write
// call, fsynced. The caller must not release credentials unless it returns nil.
func (l *auditLogger) append(rec auditRecord) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("unable to encode audit record: %w", err)
	}
	line = append(line, '\n')

	if err := ensureAuditDir(l.cfg.LogPath); err != nil {
		return err
	}
	// Cheap spool check before reading the whole log.
	if fi, err := os.Lstat(l.cfg.LogPath); err == nil && fi.Size() >= auditMaxLogBytes {
		return errAuditSpoolFull
	}
	st, err := l.open(true)
	if err != nil {
		return err
	}
	defer st.close()

	size := st.scan.size
	if size+int64(len(line)) > auditMaxLogBytes {
		return errAuditSpoolFull
	}
	if err := auditFailpoint("append_write"); err != nil {
		return err
	}
	n, err := st.f.Write(line)
	if err != nil || n != len(line) {
		_ = st.f.Truncate(size) // remove a partial record
		return fmt.Errorf("unable to append to audit log: %v", err)
	}
	if err := st.f.Sync(); err != nil {
		return fmt.Errorf("unable to fsync audit log: %w", err)
	}
	if size == 0 {
		syncDir(filepath.Dir(l.cfg.LogPath)) // newly created file
	}
	if !l.cfg.sinkConfigured() && st.cur.Offset == size {
		cur := st.cur
		cur.Offset = size + int64(len(line))
		if err := writeCursor(l.cfg.cursorPath(), cur); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

type auditStatus struct {
	SchemaVersion      int     `json:"schema_version"`
	Records            int     `json:"records"`
	Pending            int     `json:"pending"`
	DeliveryMode       string  `json:"delivery_mode"`
	OldestPendingAt    *string `json:"oldest_pending_at"`
	SinkConfigured     bool    `json:"sink_configured"`
	LastDelivery       string  `json:"last_delivery"`
	UnfinishedRequests int     `json:"unfinished_requests"`
}

func (l *auditLogger) status() (auditStatus, error) {
	s := auditStatus{
		SchemaVersion:  1,
		DeliveryMode:   l.cfg.deliveryMode(),
		SinkConfigured: l.cfg.sinkConfigured(),
		LastDelivery:   "none",
	}
	st, err := l.open(false)
	if err != nil || st == nil {
		return s, err
	}
	defer st.close()

	s.Records = len(st.scan.recs)
	pend := st.scan.pendingFrom(st.cur.Offset)
	s.Pending = len(pend)
	if len(pend) > 0 {
		t := pend[0].occurredAt
		s.OldestPendingAt = &t
	}
	if st.cur.LastDelivery != "" {
		s.LastDelivery = st.cur.LastDelivery
	}
	// A request with no final phase is a crash/kill leftover; surface it
	// rather than inventing an outcome.
	open := map[string]bool{}
	for _, r := range st.scan.recs {
		switch r.phase {
		case phaseRequested:
			open[r.eventID] = true
		case phaseEmitted, phaseBlocked, phaseApplied:
			delete(open, r.eventID)
		}
	}
	s.UnfinishedRequests = len(open)
	return s, nil
}

// ---------------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------------

type rotateResult struct {
	SchemaVersion int    `json:"schema_version"`
	Rotated       bool   `json:"rotated"`
	Archive       string `json:"archive,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

var errRotatePending = errors.New("refusing to rotate: records are still pending delivery")

// rotate archives a fully shipped log and starts a fresh 0600 log. The
// original log is left untouched on any failure.
func (l *auditLogger) rotate() (rotateResult, error) {
	res := rotateResult{SchemaVersion: 1}
	st, err := l.open(false)
	if err != nil {
		return res, err
	}
	if st == nil || len(st.scan.recs) == 0 {
		if st != nil {
			st.close()
		}
		res.Reason = "empty"
		return res, nil
	}
	defer st.close()
	if len(st.scan.pendingFrom(st.cur.Offset)) > 0 {
		return res, errRotatePending
	}

	logPath := l.cfg.LogPath
	dir := filepath.Dir(logPath)
	stamp := time.Now().UTC().Format("20060102T150405Z")

	// 1. Hard-link the log to a never-existing archive name (link refuses to
	//    replace). The log itself is still untouched.
	if err := auditFailpoint("rotate_link"); err != nil {
		return res, err
	}
	var archive string
	for i := 0; ; i++ {
		archive = logPath + "." + stamp
		if i > 0 {
			archive = fmt.Sprintf("%s.%s-%d", logPath, stamp, i)
		}
		err := os.Link(logPath, archive)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrExist) || i >= 1000 {
			return res, fmt.Errorf("unable to create archive: %w", err)
		}
	}
	undoArchive := func() { _ = os.Remove(archive) }

	// 2. Stage the fresh log and the reset cursor.
	if err := auditFailpoint("rotate_fresh"); err != nil {
		undoArchive()
		return res, err
	}
	freshTmp, err := stageFile(logPath, nil)
	if err != nil {
		undoArchive()
		return res, err
	}
	if err := auditFailpoint("rotate_cursor_stage"); err != nil {
		_ = os.Remove(freshTmp)
		undoArchive()
		return res, err
	}
	cur := st.cur
	cur.Offset = 0
	curTmp, err := stageFile(l.cfg.cursorPath(), encodeCursor(cur))
	if err != nil {
		_ = os.Remove(freshTmp)
		undoArchive()
		return res, err
	}

	// 3. Swap in the fresh log, then the cursor. If the cursor swap fails the
	//    archive is renamed back over the log, restoring the original.
	if err := commitStaged(freshTmp, logPath, "rotate_swap"); err != nil {
		_ = os.Remove(curTmp)
		undoArchive()
		return res, err
	}
	if err := commitStaged(curTmp, l.cfg.cursorPath(), "rotate_cursor_commit"); err != nil {
		if rerr := os.Rename(archive, logPath); rerr != nil {
			return res, fmt.Errorf("rotation failed and the original log could not be restored (archive: %s): %w", archive, err)
		}
		return res, err
	}
	syncDir(dir)
	res.Rotated = true
	res.Archive = archive
	return res, nil
}
