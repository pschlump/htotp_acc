package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pschlump/htotp"
)

// Canary values: none of these may ever appear in an audit log, status/flush/
// rotate output, stderr or the event-ID file.
const (
	canaryPW     = "CANARY_SUDO_PASSWORD_NEVER_LOG"
	canaryBearer = "CANARY_AUDIT_BEARER_NEVER_LOG"
	canaryEncPW  = "CANARY_ENCRYPT_PW_NEVER_LOG"
	canaryEnv    = "CANARY_ENV_VALUE_NEVER_LOG"
)

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// auditFixture is a throwaway config with one sudo entry and an audit log
// next to it.
type auditFixture struct {
	t   *testing.T
	dir string
	cfg string
	log string
	env map[string]string
}

func newAuditFixture(t *testing.T) *auditFixture {
	t.Helper()
	dir := t.TempDir()
	f := &auditFixture{t: t, dir: dir, cfg: filepath.Join(dir, "test.cfg.json"), log: filepath.Join(dir, "acc.audit.jsonl"),
		env: map[string]string{"ACC_CANARY_ENV": canaryEnv}}
	entry := fmt.Sprintf(`{"ac_config_item":[{"Name":"/myserver:phil","Username":"phil","Password":%q,"Secret":%q,"Realm":"myserver","Digits":0}]}`, canaryPW, testSecret)
	if err := os.WriteFile(f.cfg, []byte(entry), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

// run runs acc with --cfg and the fixture environment.
func (f *auditFixture) run(args ...string) (string, string, int) {
	f.t.Helper()
	return runAccEnv(f.t, f.env, append([]string{"--cfg", f.cfg}, args...)...)
}

func (f *auditFixture) sudo(args ...string) (string, string, int) {
	f.t.Helper()
	return f.run(append([]string{"--sudo-pipe", "myserver"}, args...)...)
}

func readRecords(t *testing.T, path string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var out []map[string]any
	for i, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("audit log line %d is not valid JSON: %v", i+1, err)
		}
		out = append(out, m)
	}
	return out
}

func str(m map[string]any, path ...string) string {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[p]
	}
	s, _ := cur.(string)
	return s
}

func assertNoSecrets(t *testing.T, label, text string, extra ...string) {
	t.Helper()
	for _, c := range append([]string{canaryPW, testSecret, canaryBearer, canaryEncPW, canaryEnv}, extra...) {
		if c != "" && strings.Contains(text, c) {
			t.Errorf("%s contains a secret/canary value (len %d)", label, len(c))
		}
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assertMode0600(t *testing.T, p string) {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0600 {
		t.Errorf("%s: mode %v, want regular 0600", filepath.Base(p), fi.Mode())
	}
}

func twoLines(t *testing.T, stdout string) (pw, pin string) {
	t.Helper()
	if !strings.HasSuffix(stdout, "\n") || strings.Count(stdout, "\n") != 2 {
		t.Fatalf("stdout is not exactly two newline-terminated lines (%d bytes)", len(stdout))
	}
	l := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	return l[0], l[1]
}

func assertNoCredentials(t *testing.T, stdout string) {
	t.Helper()
	if stdout != "" {
		t.Errorf("expected zero credential stdout bytes, got %d", len(stdout))
	}
}

// ---------------------------------------------------------------------------
// Test receiver
// ---------------------------------------------------------------------------

type recvReq struct {
	hdr  http.Header
	body []byte
}

type receiver struct {
	srv    *httptest.Server
	mu     sync.Mutex
	reqs   []recvReq
	status func(n int) int // n = 0-based request index
	delay  time.Duration
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	r := &receiver{status: func(int) int { return 200 }}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		n := len(r.reqs)
		r.reqs = append(r.reqs, recvReq{hdr: req.Header.Clone(), body: b})
		st, d := r.status, r.delay
		r.mu.Unlock()
		if d > 0 {
			time.Sleep(d)
		}
		w.WriteHeader(st(n))
		_, _ = w.Write([]byte("PROVIDER_BODY_NEVER_LOG"))
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) setStatus(f func(int) int) { r.mu.Lock(); r.status = f; r.mu.Unlock() }
func (r *receiver) setDelay(d time.Duration)  { r.mu.Lock(); r.delay = d; r.mu.Unlock() }
func (r *receiver) reset()                    { r.mu.Lock(); r.reqs = nil; r.mu.Unlock() }
func (r *receiver) requests() []recvReq {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recvReq(nil), r.reqs...)
}
func (r *receiver) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.reqs) }
func (r *receiver) ids() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, q := range r.reqs {
		out = append(out, q.hdr.Get("Idempotency-Key"))
	}
	return out
}

func writeToken(t *testing.T, dir, tok string) string {
	t.Helper()
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte(tok+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

type statusJSON struct {
	SchemaVersion      int     `json:"schema_version"`
	Records            int     `json:"records"`
	Pending            int     `json:"pending"`
	DeliveryMode       string  `json:"delivery_mode"`
	OldestPendingAt    *string `json:"oldest_pending_at"`
	SinkConfigured     bool    `json:"sink_configured"`
	LastDelivery       string  `json:"last_delivery"`
	UnfinishedRequests int     `json:"unfinished_requests"`
}

func (f *auditFixture) status(args ...string) statusJSON {
	f.t.Helper()
	out, errOut, code := f.run(append([]string{"--audit-status"}, args...)...)
	if code != 0 {
		f.t.Fatalf("--audit-status exit %d: %s", code, errOut)
	}
	assertNoSecrets(f.t, "status output", out+errOut)
	var s statusJSON
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		f.t.Fatalf("status is not the expected JSON object: %v (%q)", err, out)
	}
	if strings.Count(strings.TrimSpace(out), "\n") != 0 {
		f.t.Fatalf("status must be exactly one line: %q", out)
	}
	return s
}

// ---------------------------------------------------------------------------
// Protocol, event model, permissions, secrets
// ---------------------------------------------------------------------------

func TestAudit_SudoPipeTwoLinesAndRecords(t *testing.T) {
	f := newAuditFixture(t)
	idFile := filepath.Join(f.dir, "event.id")

	// Consume stdout through a real pipe, like `acc ... | ssh ... sudo -S`.
	cmd := exec.Command(accBin, "--cfg", f.cfg, "--sudo-pipe", "myserver", "--min-ttl", "3",
		"--audit-reason", "  deploy canary  ", "--audit-issue", "CHG-1", "--audit-event-id-file", idFile)
	cmd.Env = append(os.Environ(), "ACC_CANARY_ENV="+canaryEnv)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var lines []string
	sc := bufio.NewScanner(pipe)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("acc failed: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("consumer saw %d lines, want 2", len(lines))
	}
	pin := lines[1]
	if lines[0] != canaryPW {
		t.Errorf("first line is not the stored password")
	}
	if !htotp.CheckRfc6238TOTPKeyWithSkew("phil", pin, testSecret, 1, 1) {
		t.Errorf("second line is not a valid TOTP")
	}

	recs := readRecords(t, f.log)
	if len(recs) != 2 {
		t.Fatalf("want 2 records (requested, emitted), got %d", len(recs))
	}
	req, em := recs[0], recs[1]
	if str(req, "phase") != "requested" || str(em, "phase") != "emitted" {
		t.Errorf("phases = %s, %s", str(req, "phase"), str(em, "phase"))
	}
	eid := str(req, "event_id")
	if !uuidRE.MatchString(eid) || str(em, "event_id") != eid {
		t.Errorf("requested/emitted must share one UUID event_id, got %q / %q", eid, str(em, "event_id"))
	}
	if !uuidRE.MatchString(str(req, "record_id")) || str(req, "record_id") == str(em, "record_id") {
		t.Errorf("record_ids must be distinct UUIDs")
	}
	for _, r := range recs {
		if r["schema_version"] != float64(1) || str(r, "kind") != "acc.sudo_release" {
			t.Errorf("bad schema_version/kind: %v %s", r["schema_version"], str(r, "kind"))
		}
		if _, err := time.Parse(time.RFC3339Nano, str(r, "occurred_at")); err != nil || !strings.HasSuffix(str(r, "occurred_at"), "Z") {
			t.Errorf("occurred_at %q is not RFC3339Nano UTC", str(r, "occurred_at"))
		}
		if str(r, "target", "entry") != "/myserver:phil" || str(r, "target", "issuer") != "myserver" || str(r, "target", "account") != "phil" {
			t.Errorf("target = %v", r["target"])
		}
		if str(r, "request", "reason") != "deploy canary" || str(r, "request", "issue") != "CHG-1" {
			t.Errorf("request reason/issue not trimmed/recorded: %v", r["request"])
		}
		if r["request"].(map[string]any)["min_ttl_seconds"] != float64(3) || r["request"].(map[string]any)["no_reuse"] != false {
			t.Errorf("request = %v", r["request"])
		}
		if str(r, "audit", "policy") != "best-effort" || r["audit"].(map[string]any)["sink_configured"] != false {
			t.Errorf("audit = %v", r["audit"])
		}
		if str(r, "workstation", "os") == "" || str(r, "workstation", "arch") == "" || str(r, "tool", "go_version") == "" {
			t.Errorf("missing workstation/tool metadata: %v %v", r["workstation"], r["tool"])
		}
		pe := str(r, "process", "parent_executable")
		if pe == "" || strings.ContainsAny(pe, "/ \t") {
			t.Errorf("parent_executable %q must be a bare base name", pe)
		}
		if _, ok := r["process"].(map[string]any)["terminal"].(bool); !ok {
			t.Errorf("process.terminal missing")
		}
	}
	if str(req, "result", "outcome") != "requested" || str(em, "result", "outcome") != "credentials_emitted" {
		t.Errorf("outcomes: %s / %s", str(req, "result", "outcome"), str(em, "result", "outcome"))
	}

	// Event-ID file: exactly the UUID plus newline, 0600.
	if got := readFile(t, idFile); got != eid+"\n" {
		t.Errorf("event-id file = %q, want %q", got, eid+"\n")
	}
	assertMode0600(t, idFile)

	all := readFile(t, f.log) + stderr.String() + readFile(t, idFile)
	assertNoSecrets(t, "audit artifacts", all, pin)
}

func TestAudit_FilesAndDirectoryModes(t *testing.T) {
	f := newAuditFixture(t)
	logPath := filepath.Join(f.dir, "newdir", "sub", "audit.jsonl")
	if _, _, code := f.sudo("--audit-log", logPath); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, p := range []string{logPath, logPath + ".lock", logPath + ".delivery.json"} {
		assertMode0600(t, p)
	}
	for _, d := range []string{filepath.Dir(logPath), filepath.Dir(filepath.Dir(logPath))} {
		fi, err := os.Stat(d)
		if err != nil || fi.Mode().Perm() != 0700 {
			t.Errorf("created dir %s mode %v (err %v), want 0700", filepath.Base(d), fi.Mode(), err)
		}
	}
	// An existing broad directory is not chmod'ed.
	shared := filepath.Join(f.dir, "shared")
	if err := os.Mkdir(shared, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, code := f.sudo("--audit-log", filepath.Join(shared, "a.jsonl")); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if fi, _ := os.Stat(shared); fi.Mode().Perm() != 0755 {
		t.Errorf("existing directory was chmod'ed to %v", fi.Mode().Perm())
	}
	assertMode0600(t, filepath.Join(shared, "a.jsonl"))
}

func TestAudit_NoSecretsAnywhere(t *testing.T) {
	// Encrypted config: the encryption password must not leak either.
	dir := t.TempDir()
	cfg := filepath.Join(dir, "enc.cfg.json")
	env := map[string]string{"ACC_ENCRYPT_PW": canaryEncPW, "ACC_CANARY_ENV": canaryEnv}
	if _, _, code := runAccEnv(t, env, "--cfg", cfg, "--create-update", "phil", "--secret", testSecret,
		"--issuer", "myserver", "--password", canaryPW); code != 0 {
		t.Fatalf("create-update exit %d", code)
	}
	r := newReceiver(t)
	tok := writeToken(t, dir, canaryBearer)
	out, errOut, code := runAccEnv(t, env, "--cfg", cfg, "--sudo-pipe", "myserver",
		"--audit-sink", r.srv.URL, "--audit-token-file", tok)
	if code != 0 {
		t.Fatalf("sudo exit %d: %s", code, errOut)
	}
	_, pin := twoLines(t, out)
	logPath := filepath.Join(dir, "acc.audit.jsonl")
	var texts []string
	texts = append(texts, readFile(t, logPath), errOut)
	for _, args := range [][]string{{"--audit-status"}, {"--audit-flush"}} {
		o, e, _ := runAccEnv(t, env, append([]string{"--cfg", cfg, "--audit-sink", r.srv.URL, "--audit-token-file", tok}, args...)...)
		texts = append(texts, o, e)
	}
	o, e, c := runAccEnv(t, env, "--cfg", cfg, "--audit-rotate")
	if c != 0 {
		t.Fatalf("rotate exit %d: %s", c, e)
	}
	texts = append(texts, o, e)
	for _, q := range r.requests() {
		// The only place the bearer token may appear is the Authorization header.
		if q.hdr.Get("Authorization") != "Bearer "+canaryBearer {
			t.Errorf("receiver did not get the bearer token")
		}
		texts = append(texts, string(q.body))
		hdrs := q.hdr.Clone()
		hdrs.Del("Authorization")
		for k, v := range hdrs {
			texts = append(texts, k+strings.Join(v, ""))
		}
	}
	for i, tx := range texts {
		assertNoSecrets(t, fmt.Sprintf("artifact %d", i), tx, pin)
	}
	// And the raw config / parent args are not copied.
	raw := readFile(t, cfg)
	for _, tx := range texts[:1] {
		if strings.Contains(tx, strings.TrimSpace(raw)) {
			t.Errorf("raw config appears in the audit log")
		}
	}
}

// ---------------------------------------------------------------------------
// Failure handling: blocked records, no stdout
// ---------------------------------------------------------------------------

func TestAudit_ResolveFailureBlocked(t *testing.T) {
	f := newAuditFixture(t)
	out, errOut, code := f.run("--sudo-pipe", "CANARY_TYPO_PASTED_SECRET")
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	assertNoCredentials(t, out)
	recs := readRecords(t, f.log)
	if len(recs) != 2 || str(recs[0], "phase") != "requested" || str(recs[1], "phase") != "blocked" {
		t.Fatalf("want requested+blocked, got %d records", len(recs))
	}
	if str(recs[1], "result", "error_code") != "entry_resolve_failed" || str(recs[1], "result", "outcome") != "blocked" {
		t.Errorf("result = %v", recs[1]["result"])
	}
	for _, r := range recs {
		if _, has := r["target"]; has {
			t.Errorf("unresolved entry must not have a target: %v", r["target"])
		}
	}
	if strings.Contains(readFile(t, f.log), "CANARY_TYPO_PASTED_SECRET") {
		t.Errorf("unresolved user input was copied into the audit log")
	}
	_ = errOut
}

func TestAudit_GenerationFailureBlocked(t *testing.T) {
	f := newAuditFixture(t)
	state := filepath.Join(f.dir, "state.json")
	if err := os.WriteFile(state, []byte("{corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	out, _, code := f.sudo("--no-reuse", "--state", state)
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	assertNoCredentials(t, out)
	recs := readRecords(t, f.log)
	if len(recs) != 2 || str(recs[1], "phase") != "blocked" || str(recs[1], "result", "error_code") != "totp_generation_failed" {
		t.Fatalf("want requested + blocked(totp_generation_failed), got %v", recs)
	}
	if str(recs[1], "target", "entry") != "/myserver:phil" {
		t.Errorf("blocked phase of a resolved entry must carry the target")
	}
}

func TestAudit_ConfigUnavailableBlocked(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "enc.cfg.json")
	env := map[string]string{"ACC_ENCRYPT_PW": canaryEncPW}
	if _, _, code := runAccEnv(t, env, "--cfg", cfg, "--create-update", "phil", "--secret", testSecret, "--issuer", "myserver", "--password", canaryPW); code != 0 {
		t.Fatal("setup failed")
	}
	// Wrong password: the attempt is still recorded.
	out, errOut, code := runAccEnv(t, map[string]string{"ACC_ENCRYPT_PW": "wrong"}, "--cfg", cfg, "--sudo-pipe", "myserver")
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	assertNoCredentials(t, out)
	recs := readRecords(t, filepath.Join(dir, "acc.audit.jsonl"))
	recs = recs[len(recs)-2:] // the setup create-update wrote its own two records first
	if str(recs[0], "kind") != "acc.sudo_release" || str(recs[0], "phase") != "requested" ||
		str(recs[1], "phase") != "blocked" || str(recs[1], "result", "error_code") != "config_unavailable" {
		t.Fatalf("want requested + blocked(config_unavailable), got %v", recs)
	}
	assertNoSecrets(t, "stderr", errOut)
}

func TestAudit_LocalLogFailuresFailClosed(t *testing.T) {
	type tc struct {
		name  string
		setup func(f *auditFixture, log string)
	}
	cases := []tc{
		{"corrupt log", func(f *auditFixture, log string) { _ = os.WriteFile(log, []byte("not json\n"), 0600) }},
		{"partial record", func(f *auditFixture, log string) {
			_ = os.WriteFile(log, []byte(`{"schema_version":1,"record_id":"a","event_id":"b"`), 0600)
		}},
		{"symlinked log", func(f *auditFixture, log string) {
			target := filepath.Join(f.dir, "elsewhere")
			_ = os.WriteFile(target, nil, 0600)
			_ = os.Symlink(target, log)
		}},
		{"log is a directory", func(f *auditFixture, log string) { _ = os.Mkdir(log, 0700) }},
		{"log with broad permissions", func(f *auditFixture, log string) { _ = os.WriteFile(log, nil, 0644); _ = os.Chmod(log, 0644) }},
		{"unwritable log", func(f *auditFixture, log string) {
			_ = os.WriteFile(log, nil, 0400)
		}},
		{"parent is a file", func(f *auditFixture, log string) {
			_ = os.WriteFile(filepath.Join(f.dir, "blocker"), nil, 0600)
		}},
		{"cursor is a directory", func(f *auditFixture, log string) { _ = os.Mkdir(log+".delivery.json", 0700) }},
		{"cursor corrupt", func(f *auditFixture, log string) { _ = os.WriteFile(log+".delivery.json", []byte("{x"), 0600) }},
		{"cursor beyond log", func(f *auditFixture, log string) {
			_ = os.WriteFile(log, []byte(`{"schema_version":1,"record_id":"a","event_id":"b"}`+"\n"), 0600)
			_ = os.WriteFile(log+".delivery.json", []byte(`{"offset":99999}`), 0600)
		}},
		{"cursor symlink", func(f *auditFixture, log string) {
			target := filepath.Join(f.dir, "cursor-target")
			_ = os.WriteFile(target, []byte(`{"offset":0}`), 0600)
			_ = os.Symlink(target, log+".delivery.json")
		}},
		{"lock is a symlink", func(f *auditFixture, log string) {
			target := filepath.Join(f.dir, "lock-target")
			_ = os.WriteFile(target, nil, 0600)
			_ = os.Symlink(target, log+".lock")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if os.Geteuid() == 0 && c.name == "unwritable log" {
				t.Skip("root ignores file modes")
			}
			f := newAuditFixture(t)
			log := f.log
			if c.name == "parent is a file" {
				log = filepath.Join(f.dir, "blocker", "audit.jsonl")
			}
			c.setup(f, log)
			out, errOut, code := f.sudo("--audit-log", log)
			if code != 1 {
				t.Fatalf("exit %d, want 1", code)
			}
			assertNoCredentials(t, out)
			assertNoSecrets(t, "stderr", errOut)
			if !strings.Contains(errOut, "audit") {
				t.Errorf("failure must be loud on stderr: %q", errOut)
			}
		})
	}
}

func TestAudit_RequestedFailureDoesNotBurnNoReuseWindow(t *testing.T) {
	f := newAuditFixture(t)
	state := filepath.Join(f.dir, "state.json")
	_ = os.WriteFile(filepath.Join(f.dir, "blocker"), nil, 0600)
	out, _, code := f.sudo("--no-reuse", "--state", state, "--audit-log", filepath.Join(f.dir, "blocker", "a.jsonl"))
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	assertNoCredentials(t, out)
	if _, err := os.Stat(state); err == nil {
		t.Errorf("no-reuse state was written even though the requested append failed")
	}
	// With a working log the same invocation does generate (and records the window).
	out, _, code = f.sudo("--no-reuse", "--state", state)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	twoLines(t, out)
	if _, err := os.Stat(state); err != nil {
		t.Errorf("state not written on success: %v", err)
	}
}

func TestAudit_EventIDFileFailure(t *testing.T) {
	f := newAuditFixture(t)
	t.Run("missing directory", func(t *testing.T) {
		out, _, code := f.sudo("--audit-event-id-file", filepath.Join(f.dir, "nodir", "id"))
		if code != 1 {
			t.Fatalf("exit %d", code)
		}
		assertNoCredentials(t, out)
	})
	t.Run("symlink destination", func(t *testing.T) {
		target := filepath.Join(f.dir, "victim")
		_ = os.WriteFile(target, []byte("keep"), 0600)
		link := filepath.Join(f.dir, "idlink")
		_ = os.Symlink(target, link)
		out, _, code := f.sudo("--audit-event-id-file", link)
		if code != 1 {
			t.Fatalf("exit %d", code)
		}
		assertNoCredentials(t, out)
		if readFile(t, target) != "keep" {
			t.Errorf("symlink target was overwritten")
		}
	})
	// The attempts above are honestly recorded as emitted then blocked.
	recs := readRecords(t, f.log)
	last := recs[len(recs)-1]
	if str(last, "phase") != "blocked" || str(last, "result", "error_code") != "event_id_file_failed" {
		t.Errorf("last record = %v", last["result"])
	}
}

// ---------------------------------------------------------------------------
// Sink delivery and policy
// ---------------------------------------------------------------------------

func TestAudit_BestEffortSinkFailureStillReleases(t *testing.T) {
	for _, mode := range []string{"500", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			f := newAuditFixture(t)
			r := newReceiver(t)
			args := []string{"--audit-sink", r.srv.URL}
			if mode == "500" {
				r.setStatus(func(int) int { return 500 })
			} else {
				r.setDelay(1500 * time.Millisecond)
				args = append(args, "--audit-timeout", "300ms")
			}
			out, errOut, code := f.sudo(args...)
			if code != 0 {
				t.Fatalf("exit %d, want 0 (best-effort): %s", code, errOut)
			}
			twoLines(t, out)
			if !strings.Contains(errOut, "audit warning") {
				t.Errorf("expected a sanitized warning on stderr, got %q", errOut)
			}
			assertNoSecrets(t, "stderr", errOut)
			if strings.Contains(errOut, "PROVIDER_BODY_NEVER_LOG") || strings.Contains(errOut, r.srv.URL) {
				t.Errorf("stderr leaks provider text or the sink URL: %q", errOut)
			}
			s := f.status("--audit-sink", r.srv.URL)
			if s.Pending != 2 || s.DeliveryMode != "https" || !s.SinkConfigured || s.OldestPendingAt == nil {
				t.Errorf("status = %+v, want 2 pending over https", s)
			}
			if s.LastDelivery != "retryable_error" {
				t.Errorf("last_delivery = %q", s.LastDelivery)
			}
		})
	}
}

func TestAudit_RequirePolicy(t *testing.T) {
	t.Run("sink down withholds credentials", func(t *testing.T) {
		f := newAuditFixture(t)
		r := newReceiver(t)
		r.setStatus(func(int) int { return 503 })
		out, errOut, code := f.sudo("--audit-sink", r.srv.URL, "--audit-policy", "require")
		if code != 1 {
			t.Fatalf("exit %d, want 1", code)
		}
		assertNoCredentials(t, out)
		assertNoSecrets(t, "stderr", errOut)
		recs := readRecords(t, f.log)
		phases := []string{}
		for _, r := range recs {
			phases = append(phases, str(r, "phase"))
		}
		if strings.Join(phases, ",") != "requested,emitted,blocked" {
			t.Errorf("phases = %v, want requested,emitted,blocked (honest record of withheld release)", phases)
		}
		if f.status("--audit-sink", r.srv.URL).Pending != 3 {
			t.Errorf("records must remain pending for retry")
		}
	})
	t.Run("sink accepts releases credentials", func(t *testing.T) {
		f := newAuditFixture(t)
		r := newReceiver(t)
		out, _, code := f.sudo("--audit-sink", r.srv.URL, "--audit-policy", "require")
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
		twoLines(t, out)
		if r.count() != 2 {
			t.Errorf("receiver got %d records, want 2 before release", r.count())
		}
		if s := f.status("--audit-sink", r.srv.URL); s.Pending != 0 || s.LastDelivery != "accepted" {
			t.Errorf("status = %+v", s)
		}
	})
	t.Run("require without a sink is a usage error", func(t *testing.T) {
		f := newAuditFixture(t)
		out, _, code := f.sudo("--audit-policy", "require")
		if code != 2 {
			t.Fatalf("exit %d, want 2", code)
		}
		assertNoCredentials(t, out)
	})
	t.Run("bad token file withholds credentials", func(t *testing.T) {
		f := newAuditFixture(t)
		r := newReceiver(t)
		tok := filepath.Join(f.dir, "tok")
		_ = os.WriteFile(tok, []byte(canaryBearer), 0644)
		_ = os.Chmod(tok, 0644)
		out, errOut, code := f.sudo("--audit-sink", r.srv.URL, "--audit-policy", "require", "--audit-token-file", tok)
		if code != 1 {
			t.Fatalf("exit %d", code)
		}
		assertNoCredentials(t, out)
		assertNoSecrets(t, "stderr", errOut)
		if r.count() != 0 {
			t.Errorf("nothing may be sent with an unusable token file")
		}
	})
	t.Run("require through environment", func(t *testing.T) {
		f := newAuditFixture(t)
		r := newReceiver(t)
		r.setStatus(func(int) int { return 500 })
		f.env["ACC_AUDIT_SINK"] = r.srv.URL
		f.env["ACC_AUDIT_POLICY"] = "require"
		out, _, code := f.sudo()
		if code != 1 {
			t.Fatalf("exit %d", code)
		}
		assertNoCredentials(t, out)
	})
}

func TestAudit_ReceiverContract(t *testing.T) {
	f := newAuditFixture(t)
	r := newReceiver(t)
	tok := writeToken(t, f.dir, canaryBearer)
	if _, _, code := f.sudo("--audit-sink", r.srv.URL, "--audit-token-file", tok); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if r.count() != 2 {
		t.Fatalf("receiver got %d, want 2", r.count())
	}
	logLines := strings.Split(strings.TrimSuffix(readFile(t, f.log), "\n"), "\n")
	want := []string{"audit", "event_id", "kind", "occurred_at", "phase", "process", "record_id", "request", "result", "schema_version", "target", "tool", "workstation"}
	for i, q := range r.requests() {
		if q.hdr.Get("Content-Type") != "application/json" || q.hdr.Get("Accept") != "application/json" {
			t.Errorf("content negotiation headers wrong: %v", q.hdr)
		}
		if q.hdr.Get("Authorization") != "Bearer "+canaryBearer {
			t.Errorf("Authorization header wrong (token newline not trimmed?)")
		}
		var m map[string]any
		if err := json.Unmarshal(q.body, &m); err != nil {
			t.Fatalf("body is not JSON: %v", err)
		}
		if q.hdr.Get("Idempotency-Key") != str(m, "record_id") || q.hdr.Get("X-Acc-Audit-Record-Id") != str(m, "record_id") {
			t.Errorf("record id headers must equal the body record_id")
		}
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if strings.Join(keys, ",") != strings.Join(want, ",") {
			t.Errorf("top-level keys = %v, want %v", keys, want)
		}
		if string(q.body) != logLines[i] {
			t.Errorf("body %d is not the exact log record", i)
		}
	}
	if str(readRecordsFromBodies(t, r)[0], "phase") != "requested" {
		t.Errorf("records must be delivered in append order")
	}
}

func readRecordsFromBodies(t *testing.T, r *receiver) []map[string]any {
	var out []map[string]any
	for _, q := range r.requests() {
		var m map[string]any
		_ = json.Unmarshal(q.body, &m)
		out = append(out, m)
	}
	return out
}

func TestAudit_SinkURLRules(t *testing.T) {
	f := newAuditFixture(t)
	for _, tc := range []struct{ name, url string }{
		{"plain http non-loopback", "http://example.com/audit"},
		{"userinfo", "https://user:CANARY_URL_CRED@example.com/audit"},
		{"query", "https://example.com/audit?key=CANARY_URL_CRED"},
		{"scheme", "ftp://example.com/audit"},
		{"relative", "/audit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, code := f.sudo("--audit-sink", tc.url)
			if code != 2 {
				t.Fatalf("exit %d, want 2", code)
			}
			assertNoCredentials(t, out)
			if strings.Contains(errOut, "CANARY_URL_CRED") || strings.Contains(errOut, "example.com") {
				t.Errorf("stderr echoes the sink URL: %q", errOut)
			}
		})
	}
}

func TestAudit_NoRedirectFollowing(t *testing.T) {
	f := newAuditFixture(t)
	hit := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit++ }))
	defer target.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	tok := writeToken(t, f.dir, canaryBearer)
	out, _, code := f.sudo("--audit-sink", redir.URL, "--audit-token-file", tok)
	if code != 0 {
		t.Fatalf("best-effort exit %d", code)
	}
	twoLines(t, out)
	if hit != 0 {
		t.Errorf("redirect was followed (%d hits) - the bearer token would leak", hit)
	}
	if s := f.status("--audit-sink", redir.URL); s.Pending != 2 || s.LastDelivery != "config_error" {
		t.Errorf("status = %+v", s)
	}
}

func TestAudit_TokenFileRules(t *testing.T) {
	f := newAuditFixture(t)
	r := newReceiver(t)
	// Symlinked token file is refused: best-effort releases but ships nothing.
	real := writeToken(t, f.dir, canaryBearer)
	link := filepath.Join(f.dir, "toklink")
	_ = os.Symlink(real, link)
	out, errOut, code := f.sudo("--audit-sink", r.srv.URL, "--audit-token-file", link)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	twoLines(t, out)
	assertNoSecrets(t, "stderr", errOut)
	if r.count() != 0 {
		t.Errorf("sent records using a symlinked token file")
	}
	if s := f.status("--audit-sink", r.srv.URL); s.Pending != 2 || s.LastDelivery != "config_error" {
		t.Errorf("status = %+v", s)
	}
}

func TestAudit_FlushOrderedAndRetry(t *testing.T) {
	f := newAuditFixture(t)
	r := newReceiver(t)
	r.setStatus(func(int) int { return 500 })
	sink := []string{"--audit-sink", r.srv.URL}
	for i := 0; i < 2; i++ {
		if _, _, code := f.sudo(sink...); code != 0 {
			t.Fatalf("sudo %d exit %d", i, code)
		}
	}
	all := readRecords(t, f.log)
	if len(all) != 4 {
		t.Fatalf("want 4 records, got %d", len(all))
	}

	// Retryable statuses keep everything pending and stop at the first record.
	for _, st := range []int{408, 429, 503} {
		r.reset()
		r.setStatus(func(int) int { return st })
		out, errOut, code := f.run(append([]string{"--audit-flush"}, sink...)...)
		if code != 1 {
			t.Errorf("status %d: flush exit %d, want 1", st, code)
		}
		if r.count() != 1 {
			t.Errorf("status %d: flush must stop at the first unresolved record (%d requests)", st, r.count())
		}
		if !strings.Contains(out, `"retryable_error"`) {
			t.Errorf("status %d: output %q", st, out)
		}
		assertNoSecrets(t, "flush output", out+errOut)
	}

	// A non-retryable 400 stops the flush, keeps the record pending, never skips it.
	r.reset()
	r.setStatus(func(int) int { return 400 })
	out, _, code := f.run(append([]string{"--audit-flush"}, sink...)...)
	if code != 1 || r.count() != 1 || !strings.Contains(out, `"config_error"`) {
		t.Errorf("400: code=%d requests=%d out=%q", code, r.count(), out)
	}
	if s := f.status(sink...); s.Pending != 4 || s.LastDelivery != "config_error" {
		t.Errorf("after 400: %+v", s)
	}

	// Receiver recovers on the 3rd request: first two shipped in order, then it
	// fails again; the cursor must sit exactly after the second record.
	r.reset()
	r.setStatus(func(n int) int {
		if n < 2 {
			return 200
		}
		return 500
	})
	if _, _, code := f.run(append([]string{"--audit-flush"}, sink...)...); code != 1 {
		t.Errorf("partial flush must exit 1")
	}
	if s := f.status(sink...); s.Pending != 2 {
		t.Errorf("pending = %d, want 2", s.Pending)
	}
	ids := r.ids()
	if ids[0] != str(all[0], "record_id") || ids[1] != str(all[1], "record_id") {
		t.Errorf("records not shipped in append order")
	}

	// Full recovery drains the rest, in order, exit 0.
	r.reset()
	r.setStatus(func(int) int { return 200 })
	if out, _, code := f.run(append([]string{"--audit-flush"}, sink...)...); code != 0 {
		t.Fatalf("flush exit %d out %q", code, out)
	}
	ids = r.ids()
	if len(ids) != 2 || ids[0] != str(all[2], "record_id") || ids[1] != str(all[3], "record_id") {
		t.Errorf("remaining records not delivered in order: %v", ids)
	}
	if s := f.status(sink...); s.Pending != 0 || s.LastDelivery != "accepted" || s.OldestPendingAt != nil {
		t.Errorf("final status %+v", s)
	}

	// Cursor loss: everything is resent with the SAME record ids (idempotent).
	if err := os.Remove(f.log + ".delivery.json"); err != nil {
		t.Fatal(err)
	}
	r.reset()
	if _, _, code := f.run(append([]string{"--audit-flush"}, sink...)...); code != 0 {
		t.Fatalf("flush after cursor loss exit %d", code)
	}
	ids = r.ids()
	if len(ids) != 4 {
		t.Fatalf("cursor loss should resend all 4, got %d", len(ids))
	}
	for i := range ids {
		if ids[i] != str(all[i], "record_id") {
			t.Errorf("resent record %d has a different id", i)
		}
	}
}

func TestAudit_FlushWithoutSink(t *testing.T) {
	f := newAuditFixture(t)
	if _, _, code := f.sudo(); code != 0 {
		t.Fatal("sudo failed")
	}
	if out, _, code := f.run("--audit-flush"); code != 0 {
		t.Errorf("local-only flush with nothing pending: exit %d out %q", code, out)
	}
}

// ---------------------------------------------------------------------------
// Audit-only actions, usage errors, environment
// ---------------------------------------------------------------------------

func TestAudit_AuditOnlyActionsTouchNoConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "never.cfg.json")
	for _, args := range [][]string{{"--audit-status"}, {"--audit-flush"}, {"--audit-rotate"}} {
		out, errOut, code := runAccEnv(t, nil, append([]string{"--cfg", cfg}, args...)...)
		if code != 0 {
			t.Errorf("%v: exit %d (%s)", args, code, errOut)
		}
		if strings.Contains(out+errOut, "creating new config") {
			t.Errorf("%v created a config", args)
		}
	}
	if _, err := os.Stat(cfg); err == nil {
		t.Errorf("audit-only actions created the authenticator config")
	}
	// Status of a missing log creates nothing at all.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("audit-only actions on a missing log created %d file(s)", len(entries))
	}
	// An encrypted config is neither required nor decrypted (no password given).
	f := newAuditFixture(t)
	enc := filepath.Join(f.dir, "enc.cfg.json")
	if _, _, code := runAccEnv(t, map[string]string{"ACC_ENCRYPT_PW": canaryEncPW}, "--cfg", enc,
		"--create-update", "phil", "--secret", testSecret, "--issuer", "myserver"); code != 0 {
		t.Fatal("setup failed")
	}
	before := readFile(t, enc)
	if out, errOut, code := runAccEnv(t, nil, "--cfg", enc, "--audit-status"); code != 0 {
		t.Errorf("status on encrypted cfg without password: exit %d %s%s", code, out, errOut)
	}
	if readFile(t, enc) != before {
		t.Errorf("config changed by audit-only action")
	}
}

func TestAudit_UsageErrors(t *testing.T) {
	f := newAuditFixture(t)
	long := strings.Repeat("x", 513)
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"flush with sudo-pipe", []string{"--audit-flush", "--sudo-pipe", "myserver"}},
		{"status with list", []string{"--audit-status", "--list"}},
		{"two audit actions", []string{"--audit-flush", "--audit-status"}},
		{"status with reason", []string{"--audit-status", "--audit-reason", "x"}},
		{"event id file without sudo", []string{"--list", "--audit-event-id-file", "x"}},
		{"bad policy", []string{"--sudo-pipe", "myserver", "--audit-policy", "sometimes"}},
		{"timeout too small", []string{"--sudo-pipe", "myserver", "--audit-timeout", "1ms"}},
		{"timeout too large", []string{"--sudo-pipe", "myserver", "--audit-timeout", "10m"}},
		{"reason control char", []string{"--sudo-pipe", "myserver", "--audit-reason", "a\nb"}},
		{"reason too long", []string{"--sudo-pipe", "myserver", "--audit-reason", long}},
		{"issue too long", []string{"--sudo-pipe", "myserver", "--audit-issue", strings.Repeat("y", 129)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _, code := f.run(tc.args...)
			if code != 2 {
				t.Errorf("exit %d, want 2", code)
			}
			assertNoCredentials(t, out)
		})
	}
	if _, err := os.Stat(f.log); err == nil {
		t.Errorf("usage errors must not write audit records")
	}
}

func TestAudit_EnvironmentAndFlagPrecedence(t *testing.T) {
	f := newAuditFixture(t)
	envLog := filepath.Join(f.dir, "env.jsonl")
	flagLog := filepath.Join(f.dir, "flag.jsonl")
	f.env["ACC_AUDIT_LOG"] = envLog
	if _, _, code := f.sudo(); code != 0 {
		t.Fatal("sudo failed")
	}
	if len(readRecords(t, envLog)) != 2 {
		t.Errorf("$ACC_AUDIT_LOG not used")
	}
	if _, _, code := f.sudo("--audit-log", flagLog); code != 0 {
		t.Fatal("sudo failed")
	}
	if len(readRecords(t, flagLog)) != 2 || len(readRecords(t, envLog)) != 2 {
		t.Errorf("--audit-log must override the environment")
	}
	// An explicit empty --audit-sink forces local-only despite $ACC_AUDIT_SINK;
	// it never disables the local record.
	r := newReceiver(t)
	f.env["ACC_AUDIT_SINK"] = r.srv.URL
	if _, _, code := f.sudo("--audit-sink", ""); code != 0 {
		t.Fatal("sudo failed")
	}
	if r.count() != 0 {
		t.Errorf("--audit-sink '' did not override the environment")
	}
	if len(readRecords(t, envLog)) != 4 {
		t.Errorf("local record must still be written")
	}
}

// ---------------------------------------------------------------------------
// Rotation and local-only mode
// ---------------------------------------------------------------------------

func TestAudit_LocalOnlyAndRotation(t *testing.T) {
	f := newAuditFixture(t)
	if _, _, code := f.sudo(); code != 0 {
		t.Fatal("sudo failed")
	}
	s := f.status()
	if s.DeliveryMode != "local_only" || s.Pending != 0 || s.Records != 2 || s.SinkConfigured || s.OldestPendingAt != nil {
		t.Errorf("local-only status = %+v", s)
	}
	orig := readFile(t, f.log)

	out, errOut, code := f.run("--audit-rotate")
	if code != 0 {
		t.Fatalf("rotate exit %d: %s", code, errOut)
	}
	var rr struct {
		Rotated bool   `json:"rotated"`
		Archive string `json:"archive"`
	}
	if err := json.Unmarshal([]byte(out), &rr); err != nil || !rr.Rotated || rr.Archive == "" {
		t.Fatalf("rotate output %q", out)
	}
	if readFile(t, rr.Archive) != orig {
		t.Errorf("archive does not preserve the complete local log")
	}
	assertMode0600(t, rr.Archive)
	assertMode0600(t, f.log)
	if readFile(t, f.log) != "" {
		t.Errorf("fresh log must be empty")
	}
	if s := f.status(); s.Records != 0 || s.Pending != 0 {
		t.Errorf("post-rotate status %+v", s)
	}

	// Enable a sink later: archived/pre-configuration records are NOT backfilled.
	r := newReceiver(t)
	if _, _, code := f.sudo(); code != 0 { // local-only record in the fresh log
		t.Fatal("sudo failed")
	}
	sink := []string{"--audit-sink", r.srv.URL}
	if s := f.status(sink...); s.Pending != 0 || s.DeliveryMode != "https" {
		t.Errorf("enabling a sink must not mark old records pending: %+v", s)
	}
	if _, _, code := f.run(append([]string{"--audit-flush"}, sink...)...); code != 0 || r.count() != 0 {
		t.Errorf("flush after enabling sink sent %d old records", r.count())
	}
	if _, _, code := f.sudo(sink...); code != 0 {
		t.Fatal("sudo failed")
	}
	if r.count() != 2 {
		t.Errorf("receiver should get exactly the 2 new records, got %d", r.count())
	}
	// Rotating an empty/absent log is a harmless no-op.
	g := newAuditFixture(t)
	if out, _, code := g.run("--audit-rotate"); code != 0 || !strings.Contains(out, `"rotated":false`) {
		t.Errorf("rotate of missing log: %d %q", code, out)
	}
}

func TestAudit_RotateRefusesPending(t *testing.T) {
	f := newAuditFixture(t)
	r := newReceiver(t)
	r.setStatus(func(int) int { return 500 })
	sink := []string{"--audit-sink", r.srv.URL}
	if _, _, code := f.sudo(sink...); code != 0 {
		t.Fatal("sudo failed")
	}
	before := readFile(t, f.log)
	out, errOut, code := f.run("--audit-rotate")
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if out != "" || !strings.Contains(errOut, "pending") {
		t.Errorf("out=%q err=%q", out, errOut)
	}
	if readFile(t, f.log) != before {
		t.Errorf("log changed by refused rotation")
	}
	if len(globArchives(t, f.log)) != 0 {
		t.Errorf("archive created despite pending records")
	}
}

func globArchives(t *testing.T, log string) []string {
	t.Helper()
	m, _ := filepath.Glob(log + ".20*")
	return m
}

// ---------------------------------------------------------------------------
// Config-change events
// ---------------------------------------------------------------------------

func TestAudit_ConfigChangeEvents(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "c.cfg.json")
	logPath := filepath.Join(dir, "acc.audit.jsonl")
	env := map[string]string{"ACC_CANARY_ENV": canaryEnv}
	run := func(args ...string) (string, string, int) {
		return runAccEnv(t, env, append([]string{"--cfg", cfg}, args...)...)
	}
	if _, _, c := run("--create-update", "phil", "--secret", testSecret, "--issuer", "myserver", "--password", canaryPW,
		"--audit-reason", "initial setup", "--audit-issue", "CHG-9"); c != 0 {
		t.Fatal("create-update failed")
	}
	enrollOut, _, c := run("--enroll", "jake", "--issuer", "myserver", "--password", canaryPW, "--qr", filepath.Join(dir, "q.png"))
	if c != 0 {
		t.Fatal("enroll failed")
	}
	enrollSecret := ""
	for _, l := range strings.Split(enrollOut, "\n") {
		if strings.HasPrefix(l, "Secret: ") {
			enrollSecret = strings.TrimPrefix(l, "Secret: ")
		}
	}
	if enrollSecret == "" {
		t.Fatal("no enroll secret in output")
	}
	if _, _, c := run("--import", "tests/example-QR.png"); c != 0 {
		t.Fatal("import failed")
	}
	if _, _, c := run("--delete", "jake"); c != 0 {
		t.Fatal("delete failed")
	}
	// A delete that finds nothing mutates nothing and records nothing.
	if _, _, c := run("--delete", "no-such-entry"); c != 0 {
		t.Fatal("delete of unknown failed")
	}

	recs := readRecords(t, logPath)
	if len(recs) != 8 {
		t.Fatalf("want 8 records (4 operations x requested/applied), got %d", len(recs))
	}
	wantAct := []string{"create_update", "enroll", "import", "delete"}
	wantEntry := []string{"/myserver:phil", "/myserver:jake", "", "/myserver:jake"}
	for i, act := range wantAct {
		rq, ap := recs[2*i], recs[2*i+1]
		if str(rq, "kind") != "acc.config_change" || str(rq, "phase") != "requested" || str(ap, "phase") != "applied" {
			t.Errorf("op %d phases/kind: %s %s %s", i, str(rq, "kind"), str(rq, "phase"), str(ap, "phase"))
		}
		if str(rq, "event_id") != str(ap, "event_id") {
			t.Errorf("op %d: requested/applied must share an event_id", i)
		}
		if str(rq, "change", "action") != act || str(ap, "change", "action") != act {
			t.Errorf("op %d action = %q, want %q", i, str(rq, "change", "action"), act)
		}
		if wantEntry[i] != "" && str(ap, "target", "entry") != wantEntry[i] {
			t.Errorf("op %d entry = %q, want %q", i, str(ap, "target", "entry"), wantEntry[i])
		}
		if str(ap, "target", "entry") == "" {
			t.Errorf("op %d has no canonical target", i)
		}
		if str(ap, "result", "outcome") != "applied" {
			t.Errorf("op %d outcome %q", i, str(ap, "result", "outcome"))
		}
	}
	if str(recs[0], "change", "reason") != "initial setup" || str(recs[0], "change", "issue") != "CHG-9" {
		t.Errorf("reason/issue not recorded: %v", recs[0]["change"])
	}

	// No secrets, URIs, QR data or config body.
	logText := readFile(t, logPath)
	assertNoSecrets(t, "audit log", logText, enrollSecret)
	for _, bad := range []string{"otpauth://", "\"secret\"", "\"password\"", "\"Secret\"", "\"Password\"", "ac_config_item"} {
		if strings.Contains(logText, bad) {
			t.Errorf("audit log contains %q", bad)
		}
	}
	// The imported QR's secret is in the config, not in the audit log.
	var doc struct {
		Items []ACConfigItem `json:"ac_config_item"`
	}
	_ = json.Unmarshal([]byte(readFile(t, cfg)), &doc)
	for _, it := range doc.Items {
		if it.Secret != "" && strings.Contains(logText, it.Secret) {
			t.Errorf("a stored secret appears in the audit log")
		}
	}
}

func TestAudit_ConfigChangeBlockedByAuditFailure(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "c.cfg.json")
	_ = os.WriteFile(filepath.Join(dir, "blocker"), nil, 0600)
	_, errOut, code := runAccEnv(t, nil, "--cfg", cfg, "--audit-log", filepath.Join(dir, "blocker", "a.jsonl"),
		"--create-update", "phil", "--secret", testSecret, "--issuer", "myserver")
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if strings.Contains(readFile(t, cfg), "phil") {
		t.Errorf("config was mutated although the audit append failed")
	}
	_ = errOut
}

func TestAudit_ConfigChangeSinkFailureDoesNotRollBack(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "c.cfg.json")
	r := newReceiver(t)
	r.setStatus(func(int) int { return 500 })
	out, errOut, code := runAccEnv(t, nil, "--cfg", cfg, "--audit-sink", r.srv.URL, "--audit-policy", "require",
		"--create-update", "phil", "--secret", testSecret, "--issuer", "myserver")
	if code != 0 {
		t.Fatalf("exit %d, want 0 (config is not rolled back)", code)
	}
	if !strings.Contains(out, "Successfully imported") || !strings.Contains(errOut, "audit warning") {
		t.Errorf("out=%q err=%q", out, errOut)
	}
	if !strings.Contains(readFile(t, cfg), "phil") {
		t.Errorf("config mutation lost")
	}
}

// ---------------------------------------------------------------------------
// Spool limit and concurrency
// ---------------------------------------------------------------------------

func TestAudit_SpoolLimitRefusesRelease(t *testing.T) {
	f := newAuditFixture(t)
	line := `{"schema_version":1,"record_id":"r","event_id":"e","kind":"acc.sudo_release","phase":"emitted","occurred_at":"2026-01-01T00:00:00Z"}` + "\n"
	big := strings.Repeat(line, (auditDefaultMaxLogBytes/len(line))+2)
	if err := os.WriteFile(f.log, []byte(big), 0600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := f.sudo()
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	assertNoCredentials(t, out)
	if !strings.Contains(errOut, "spool is full") {
		t.Errorf("stderr = %q", errOut)
	}
	if readFile(t, f.log) != big {
		t.Errorf("events were dropped or modified at the spool limit")
	}
}

func TestAudit_ConcurrentProcesses(t *testing.T) {
	f := newAuditFixture(t)
	r := newReceiver(t)
	sink := []string{"--audit-sink", r.srv.URL}
	const nSudo = 8

	var wg sync.WaitGroup
	outs := make([]string, nSudo)
	codes := make([]int, nSudo)
	for i := 0; i < nSudo; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outs[i], _, codes[i] = runAccEnvQuiet(f.env, append([]string{"--cfg", f.cfg, "--sudo-pipe", "myserver"}, sink...)...)
		}()
	}
	for i := 0; i < 3; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			runAccEnvQuiet(f.env, append([]string{"--cfg", f.cfg, "--audit-flush"}, sink...)...)
		}()
		go func() {
			defer wg.Done()
			runAccEnvQuiet(f.env, append([]string{"--cfg", f.cfg, "--audit-status"}, sink...)...)
		}()
		go func() { defer wg.Done(); runAccEnvQuiet(f.env, "--cfg", f.cfg, "--audit-rotate") }()
	}
	wg.Wait()
	for i := range outs {
		if codes[i] != 0 {
			t.Fatalf("sudo %d exit %d", i, codes[i])
		}
		twoLines(t, outs[i])
	}
	if _, _, code := f.run(append([]string{"--audit-flush"}, sink...)...); code != 0 {
		t.Fatalf("final flush exit %d", code)
	}

	// Every record, in the live log and all archives, is intact, unique and complete.
	files := append(globArchives(t, f.log), f.log)
	seen := map[string]bool{}
	phases := map[string]map[string]bool{}
	for _, p := range files {
		for _, rec := range readRecords(t, p) {
			id := str(rec, "record_id")
			if seen[id] {
				t.Errorf("duplicate record_id in local logs")
			}
			seen[id] = true
			ev := str(rec, "event_id")
			if phases[ev] == nil {
				phases[ev] = map[string]bool{}
			}
			phases[ev][str(rec, "phase")] = true
		}
		assertMode0600(t, p)
	}
	if len(seen) != 2*nSudo || len(phases) != nSudo {
		t.Errorf("records=%d events=%d, want %d / %d (lost or interleaved)", len(seen), len(phases), 2*nSudo, nSudo)
	}
	for ev, ph := range phases {
		if !ph["requested"] || !ph["emitted"] {
			t.Errorf("event %s incomplete: %v", ev, ph)
		}
	}
	got := map[string]bool{}
	for _, id := range r.ids() {
		got[id] = true
	}
	for id := range seen {
		if !got[id] {
			t.Errorf("record %s never reached the sink", id)
		}
	}
	if s := f.status(sink...); s.Pending != 0 {
		t.Errorf("pending = %d after final flush", s.Pending)
	}
}

// runAccEnvQuiet is runAccEnv without *testing.T (usable from goroutines).
func runAccEnvQuiet(extraEnv map[string]string, args ...string) (string, string, int) {
	cmd := exec.Command(accBin, args...)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "ACC_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	for k, v := range extraEnv {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	code := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return o.String(), e.String(), code
}
