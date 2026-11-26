package main

// Audit logging for acc: configuration, event model and metadata.
//
// The audit log records credential releases (--sudo-pipe) and config
// mutations. Records are built from the explicit structs below - never from
// ACConfigItem/GlobalConfigData - so a secret cannot leak by field addition.
// Storage lives in audit_store.go, HTTPS shipping in audit_ship.go and the CLI
// wiring in audit_cli.go.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	auditSchemaVersion = 1

	auditKindSudo   = "acc.sudo_release"
	auditKindConfig = "acc.config_change"

	phaseRequested = "requested"
	phaseEmitted   = "emitted"
	phaseBlocked   = "blocked"
	phaseApplied   = "applied"

	policyBestEffort = "best-effort"
	policyRequire    = "require"

	auditSinkJSON = "json"
	auditSinkLoki = "loki"

	auditMaxReason = 512
	auditMaxIssue  = 128

	auditDefaultTimeout = 2 * time.Second
	auditMinTimeout     = 100 * time.Millisecond
	auditMaxTimeout     = 30 * time.Second

	// auditDefaultMaxLogBytes bounds the local spool. At the limit new
	// credential releases are refused until events are shipped and rotated.
	auditDefaultMaxLogBytes = 64 << 20

	// auditLockWait bounds how long a process waits for the audit lock.
	auditLockWait = 10 * time.Second
)

// auditMaxLogBytes is a variable so tests can lower it.
var auditMaxLogBytes int64 = auditDefaultMaxLogBytes

var (
	errAuditLockTimeout = errors.New("timed out waiting for the audit lock")
	errAuditSpoolFull   = errors.New("audit spool is full: ship pending events and run --audit-rotate before releasing more credentials")
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// auditConfig is the resolved audit configuration (flags over environment).
type auditConfig struct {
	LogPath     string
	SinkURL     string
	SinkFormat  string
	TokenFile   string
	Policy      string
	Timeout     time.Duration
	Reason      string
	Issue       string
	EventIDFile string
}

func (c *auditConfig) lockPath() string   { return c.LogPath + ".lock" }
func (c *auditConfig) cursorPath() string { return c.LogPath + ".delivery.json" }
func (c *auditConfig) sinkConfigured() bool {
	return c.SinkURL != ""
}
func (c *auditConfig) resolvedSinkFormat() string {
	if c.SinkFormat == "" {
		return auditSinkJSON
	}
	return c.SinkFormat
}
func (c *auditConfig) deliveryMode() string {
	if c.sinkConfigured() {
		return "https"
	}
	return "local_only"
}

// validateSinkURL checks the sink URL without ever echoing it (it might carry
// credentials): https always, plain http only for loopback receivers, and no
// userinfo, query or fragment.
func validateSinkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("audit sink is not a valid absolute URL")
	}
	if u.User != nil {
		return errors.New("audit sink URL must not contain credentials (userinfo)")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("audit sink URL must not contain a query string or fragment")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return errors.New("audit sink must use https (plain http is allowed only for loopback receivers)")
	default:
		return errors.New("audit sink must use https")
	}
}

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// validateAuditText trims s and rejects invalid UTF-8, control characters and
// oversized values.
func validateAuditText(name, s string, max int) (string, error) {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("%s is not valid UTF-8", name)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("%s must not contain control characters", name)
		}
	}
	if len(s) > max {
		return "", fmt.Errorf("%s is longer than %d bytes", name, max)
	}
	return s, nil
}

// boundAuditText makes a config-derived string safe and bounded for the log.
func boundAuditText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r == utf8.RuneError || unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// ---------------------------------------------------------------------------
// Event model
// ---------------------------------------------------------------------------

type auditTool struct {
	GitCommit string `json:"git_commit"`
	GitTag    string `json:"git_tag"`
	GoVersion string `json:"go_version"`
}

type auditWorkstation struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Username string `json:"username"`
}

type auditProcess struct {
	PID              int    `json:"pid"`
	PPID             int    `json:"ppid"`
	ParentExecutable string `json:"parent_executable"`
	Terminal         bool   `json:"terminal"`
}

type auditRequest struct {
	MinTTLSeconds uint   `json:"min_ttl_seconds"`
	NoReuse       bool   `json:"no_reuse"`
	Reason        string `json:"reason"`
	Issue         string `json:"issue"`
}

type auditChange struct {
	Action string `json:"action"`
	Reason string `json:"reason"`
	Issue  string `json:"issue"`
}

type auditTarget struct {
	Entry   string `json:"entry"`
	Issuer  string `json:"issuer"`
	Account string `json:"account"`
}

type auditInfo struct {
	Policy         string `json:"policy"`
	SinkConfigured bool   `json:"sink_configured"`
}

type auditResult struct {
	Outcome   string `json:"outcome"`
	ErrorCode string `json:"error_code,omitempty"`
}

type auditRecord struct {
	SchemaVersion int              `json:"schema_version"`
	RecordID      string           `json:"record_id"`
	EventID       string           `json:"event_id"`
	Kind          string           `json:"kind"`
	Phase         string           `json:"phase"`
	OccurredAt    string           `json:"occurred_at"`
	Tool          auditTool        `json:"tool"`
	Workstation   auditWorkstation `json:"workstation"`
	Process       auditProcess     `json:"process"`
	Request       *auditRequest    `json:"request,omitempty"`
	Change        *auditChange     `json:"change,omitempty"`
	Target        *auditTarget     `json:"target,omitempty"`
	Audit         auditInfo        `json:"audit"`
	Result        auditResult      `json:"result"`
}

// auditOp is one audited operation: the data shared by all of its phases.
type auditOp struct {
	EventID string
	base    auditRecord
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func newAuditOp(kind string, ac *auditConfig) *auditOp {
	op := &auditOp{EventID: newUUID()}
	op.base = auditRecord{
		SchemaVersion: auditSchemaVersion,
		EventID:       op.EventID,
		Kind:          kind,
		Tool:          auditTool{GitCommit: GitCommit, GitTag: GitTag, GoVersion: runtime.Version()},
		Workstation:   workstationInfo(),
		Process:       processInfo(),
		Audit:         auditInfo{Policy: ac.Policy, SinkConfigured: ac.sinkConfigured()},
	}
	return op
}

// setTarget records the canonical, resolved entry. Never call it with a
// user-supplied unresolved string.
func (op *auditOp) setTarget(item ACConfigItem) {
	name := item.Name
	if !strings.HasPrefix(name, "/") {
		name = "/" + name
	}
	op.base.Target = &auditTarget{
		Entry:   boundAuditText(name, 256),
		Issuer:  boundAuditText(item.Realm, 256),
		Account: boundAuditText(item.Username, 256),
	}
}

// rec stamps a new record for the given phase.
func (op *auditOp) rec(phase, outcome, errCode string) auditRecord {
	r := op.base
	r.RecordID = newUUID()
	r.Phase = phase
	r.OccurredAt = time.Now().UTC().Format(time.RFC3339Nano)
	r.Result = auditResult{Outcome: outcome, ErrorCode: errCode}
	return r
}

func workstationInfo() auditWorkstation {
	w := auditWorkstation{OS: runtime.GOOS, Arch: runtime.GOARCH}
	if h, err := os.Hostname(); err == nil {
		w.Hostname = boundAuditText(h, 256)
	}
	if u, err := user.Current(); err == nil {
		w.Username = boundAuditText(u.Username, 128)
	}
	return w
}

func processInfo() auditProcess {
	p := auditProcess{PID: os.Getpid(), PPID: os.Getppid()}
	p.ParentExecutable = parentExecutableName(p.PPID)
	if fi, err := os.Stdin.Stat(); err == nil {
		p.Terminal = fi.Mode()&os.ModeCharDevice != 0
	}
	return p
}

// parentExecutableName returns only the base name of the parent process
// executable - never its arguments or environment.
func parentExecutableName(ppid int) string {
	var name string
	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile("/proc/" + strconv.Itoa(ppid) + "/comm"); err == nil {
			name = string(b)
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/bin/ps", "-o", "comm=", "-p", strconv.Itoa(ppid))
		cmd.Env = []string{}
		if b, err := cmd.Output(); err == nil {
			name = string(b)
		}
	}
	name = strings.TrimSpace(name)
	name = strings.TrimPrefix(filepath.Base(name), "-") // login shells show as "-zsh"
	if name == "." || name == string(filepath.Separator) {
		name = ""
	}
	if name == "" {
		return "unknown"
	}
	return boundAuditText(name, 64)
}
