package main

// CLI surface and orchestration for audit logging: flags, configuration
// resolution, the standalone --audit-* actions, the --sudo-pipe lifecycle and
// config-change auditing.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var AuditLog = flag.String("audit-log", "", "JSONL audit log. Defaults to $ACC_AUDIT_LOG, else acc.audit.jsonl next to --cfg.")
var AuditSink = flag.String("audit-sink", "", "Optional HTTPS audit event receiver. Defaults to $ACC_AUDIT_SINK. Empty means local-only logging.")
var AuditSinkFormat = flag.String("audit-sink-format", "", "Sink payload: json|loki. Defaults to $ACC_AUDIT_SINK_FORMAT, else json. For Loki, use its push API URL, including any reverse-proxy prefix.")
var AuditTokenFile = flag.String("audit-token-file", "", "File (0600) holding the sink bearer token. Defaults to $ACC_AUDIT_TOKEN_FILE.")
var AuditPolicy = flag.String("audit-policy", "", "best-effort|require. Defaults to $ACC_AUDIT_POLICY, else best-effort. Local append is mandatory under both; require also needs remote acceptance before credentials are released.")
var AuditTimeout = flag.Duration("audit-timeout", auditDefaultTimeout, "Per-delivery-attempt timeout (100ms..30s). One total budget for --sudo-pipe, per request for --audit-flush.")
var AuditReason = flag.String("audit-reason", "", "Optional operator/deployment reason recorded in the audit log (max 512 bytes).")
var AuditIssue = flag.String("audit-issue", "", "Optional issue/incident/change reference recorded in the audit log (max 128 bytes).")
var AuditEventIDFile = flag.String("audit-event-id-file", "", "With --sudo-pipe: write the release's event UUID to this 0600 file (never to stdout).")
var AuditFlush = flag.Bool("audit-flush", false, "Standalone: retry pending audit sink delivery in append order. Exit 0 only when nothing remains pending.")
var AuditStatus = flag.Bool("audit-status", false, "Standalone: print one content-free JSON status object for the audit log.")
var AuditRotate = flag.Bool("audit-rotate", false, "Standalone: archive a fully shipped audit log and start a fresh one. Refuses while records are pending.")

// auditClientFactory is replaceable in tests.
var auditClientFactory = newAuditHTTPClient

func flagWasSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// auditPick returns the flag value if the flag was given (even if empty, so
// "--audit-sink ”" forces local-only), else the environment value.
func auditPick(flagName string, val *string, env string) string {
	if flagWasSet(flagName) {
		return *val
	}
	return os.Getenv(env)
}

// resolveAuditConfig merges flags and environment and validates them. Errors
// are usage errors (exit 2) and never echo the sink URL.
func resolveAuditConfig() (*auditConfig, error) {
	c := &auditConfig{Timeout: *AuditTimeout}

	c.LogPath = auditPick("audit-log", AuditLog, "ACC_AUDIT_LOG")
	if c.LogPath == "" {
		c.LogPath = filepath.Join(filepath.Dir(*Cfg), "acc.audit.jsonl")
	}
	if abs, err := filepath.Abs(c.LogPath); err == nil {
		c.LogPath = abs
	}

	c.SinkURL = strings.TrimSpace(auditPick("audit-sink", AuditSink, "ACC_AUDIT_SINK"))
	if c.SinkURL != "" {
		if err := validateSinkURL(c.SinkURL); err != nil {
			return nil, err
		}
	}
	c.SinkFormat = strings.TrimSpace(auditPick("audit-sink-format", AuditSinkFormat, "ACC_AUDIT_SINK_FORMAT"))
	if c.SinkFormat == "" {
		c.SinkFormat = auditSinkJSON
	}
	if c.SinkFormat != auditSinkJSON && c.SinkFormat != auditSinkLoki {
		return nil, errors.New("--audit-sink-format must be json or loki")
	}
	c.TokenFile = auditPick("audit-token-file", AuditTokenFile, "ACC_AUDIT_TOKEN_FILE")

	c.Policy = strings.TrimSpace(auditPick("audit-policy", AuditPolicy, "ACC_AUDIT_POLICY"))
	switch c.Policy {
	case "":
		c.Policy = policyBestEffort
	case policyBestEffort, policyRequire:
	default:
		return nil, errors.New("--audit-policy must be best-effort or require")
	}
	if c.Policy == policyRequire && c.SinkURL == "" {
		return nil, errors.New("--audit-policy require needs an audit sink (--audit-sink or $ACC_AUDIT_SINK)")
	}
	if c.Timeout < auditMinTimeout || c.Timeout > auditMaxTimeout {
		return nil, fmt.Errorf("--audit-timeout must be between %s and %s", auditMinTimeout, auditMaxTimeout)
	}

	var err error
	if c.Reason, err = validateAuditText("--audit-reason", *AuditReason, auditMaxReason); err != nil {
		return nil, err
	}
	if c.Issue, err = validateAuditText("--audit-issue", *AuditIssue, auditMaxIssue); err != nil {
		return nil, err
	}
	c.EventIDFile = *AuditEventIDFile
	return c, nil
}

// auditUsageCheck rejects incompatible flag combinations.
func auditUsageCheck() error {
	n := 0
	for _, b := range []bool{*AuditStatus, *AuditFlush, *AuditRotate} {
		if b {
			n++
		}
	}
	other := *Import != "" || *LogFilePath != "" || *CreateUpdate != "" || *Delete != "" || *List ||
		*Get2fa != "" || *SudoPipe != "" || *Enroll != "" || *CheckTime != "" || *GetSecret != "" ||
		*CreateNewSecret || *GenQR != "" || *Verify != ""
	if n > 1 {
		return errors.New("--audit-status, --audit-flush and --audit-rotate are mutually exclusive")
	}
	if n == 1 {
		if other {
			return errors.New("--audit-status/--audit-flush/--audit-rotate are standalone actions and cannot be combined with other actions")
		}
		if *AuditReason != "" || *AuditIssue != "" || *AuditEventIDFile != "" {
			return errors.New("--audit-reason/--audit-issue/--audit-event-id-file do not apply to audit-only actions")
		}
	}
	if *AuditEventIDFile != "" && *SudoPipe == "" {
		return errors.New("--audit-event-id-file requires --sudo-pipe")
	}
	return nil
}

func usageExit(err error) {
	fmt.Fprintf(os.Stderr, "acc: %s\n", err)
	os.Exit(2)
}

// auditFatal reports a local audit failure and exits 1. Credentials must not
// have been written before this is called.
func auditFatal(err error) {
	fmt.Fprintf(os.Stderr, "acc: audit failure: %s\n", err)
	os.Exit(1)
}

func auditWarn(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "acc: audit warning: "+format+"\n", a...)
}

// ---------------------------------------------------------------------------
// Standalone actions (run before any config file is created or decrypted)
// ---------------------------------------------------------------------------

func printJSON(v any) {
	b, _ := json.Marshal(v)
	fmt.Printf("%s\n", b)
}

// runAuditAction runs --audit-status/--audit-flush/--audit-rotate and returns
// the process exit code.
func runAuditAction(ac *auditConfig) int {
	l := newAuditLogger(ac)
	switch {
	case *AuditStatus:
		s, err := l.status()
		if err != nil {
			fmt.Fprintf(os.Stderr, "acc: audit status failed: %s\n", err)
			return 1
		}
		printJSON(s)
		return 0

	case *AuditRotate:
		r, err := l.rotate()
		if err != nil {
			fmt.Fprintf(os.Stderr, "acc: audit rotate failed: %s\n", err)
			return 1
		}
		printJSON(r)
		return 0

	default: // --audit-flush
		if !ac.sinkConfigured() {
			s, err := l.status()
			if err != nil {
				fmt.Fprintf(os.Stderr, "acc: audit flush failed: %s\n", err)
				return 1
			}
			if s.Pending > 0 {
				fmt.Fprintf(os.Stderr, "acc: audit flush: %d record(s) pending but no audit sink is configured\n", s.Pending)
				return 1
			}
			printJSON(map[string]any{"schema_version": 1, "outcome": deliveryAccepted, "pending": 0})
			return 0
		}
		res, err := l.ship(auditClientFactory(), false, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "acc: audit flush failed: %s\n", err)
			return 1
		}
		out := map[string]any{"schema_version": 1, "outcome": res.Outcome, "pending": res.Pending}
		if res.HTTPStatus != 0 {
			out["http_status"] = res.HTTPStatus
		}
		printJSON(out)
		if res.Pending > 0 {
			fmt.Fprintf(os.Stderr, "acc: audit flush incomplete (%s): %d record(s) remain pending\n", res.Outcome, res.Pending)
			return 1
		}
		return 0
	}
}

// ---------------------------------------------------------------------------
// --sudo-pipe lifecycle
// ---------------------------------------------------------------------------

// deliverAfterAppend ships pending records after appending upTo. Under
// best-effort a failure only warns (returns nil); under require it returns an
// error and the caller withholds credentials.
func deliverAfterAppend(l *auditLogger, upTo string) error {
	if !l.cfg.sinkConfigured() {
		return nil
	}
	res, err := l.ship(auditClientFactory(), true, upTo)
	if err != nil {
		return err // local failure: always fatal for a release
	}
	if res.Reached {
		return nil
	}
	if l.cfg.Policy == policyRequire {
		return fmt.Errorf("required audit delivery failed (%s)", res.Outcome)
	}
	auditWarn("delivery to the audit sink is incomplete (%s); %d record(s) remain pending - retry with --audit-flush", res.Outcome, res.Pending)
	return nil
}

func sudoBlocked(l *auditLogger, op *auditOp, code string) {
	if err := l.append(op.rec(phaseBlocked, "blocked", code)); err != nil {
		auditWarn("unable to record the blocked phase: %s", err)
	}
}

// willRunSudoPipe reports whether main's dispatch will reach --sudo-pipe.
func willRunSudoPipe() bool {
	return *SudoPipe != "" && *Import == "" && *LogFilePath == "" && *CreateUpdate == "" &&
		*Delete == "" && !*List && *Get2fa == ""
}

func newSudoOp(ac *auditConfig) *auditOp {
	op := newAuditOp(auditKindSudo, ac)
	op.base.Request = &auditRequest{MinTTLSeconds: *MinTTL, NoReuse: *NoReuse, Reason: ac.Reason, Issue: ac.Issue}
	return op
}

// sudoConfigFail records a --sudo-pipe attempt that never got as far as
// reading the config (missing password, wrong password, unreadable file).
func sudoConfigFail(ac *auditConfig) {
	if ac == nil || !willRunSudoPipe() {
		return
	}
	l := newAuditLogger(ac)
	op := newSudoOp(ac)
	if err := l.append(op.rec(phaseRequested, "requested", "")); err != nil {
		auditWarn("%s", err)
		return
	}
	sudoBlocked(l, op, "config_unavailable")
}

// sudoExit is a failed --sudo-pipe: the exit code and the stderr message.
type sudoExit struct {
	code int
	msg  string
}

// runSudoPipe runs the audited release and writes the result.
func runSudoPipe(ac *auditConfig) {
	out, fail := sudoPipe(ac)
	if fail != nil {
		fmt.Fprintf(os.Stderr, "%s\n", fail.msg)
		os.Exit(fail.code)
	}
	// Exactly two lines, one write, checked.
	if n, err := os.Stdout.Write(out); err != nil || n != len(out) {
		fmt.Fprintf(os.Stderr, "acc: unable to write credentials to stdout\n")
		os.Exit(1)
	}
}

// sudoPipe produces "<password>\n<totp>\n" for the entry, auditing every step.
// It returns the credential bytes only after every required audit step has
// succeeded; on any failure it returns nil bytes.
func sudoPipe(ac *auditConfig) ([]byte, *sudoExit) {
	l := newAuditLogger(ac)
	op := newSudoOp(ac)
	auditFail := func(err error) *sudoExit {
		return &sudoExit{1, "acc: audit failure: " + err.Error()}
	}

	pos, rerr := ResolveName(gCfg.Local, *SudoPipe)
	if rerr == nil {
		op.setTarget(gCfg.Local[pos])
	}

	// 1. Durable `requested` BEFORE anything is generated or burned.
	if err := l.append(op.rec(phaseRequested, "requested", "")); err != nil {
		return nil, auditFail(err)
	}

	if ac.Policy == policyRequire {
		if _, err := loadAuditToken(ac.TokenFile); err != nil {
			sudoBlocked(l, op, "audit_sink_config_invalid")
			return nil, auditFail(err)
		}
	}

	// 2. Resolve.
	if rerr != nil {
		sudoBlocked(l, op, "entry_resolve_failed")
		return nil, &sudoExit{1, rerr.Error()}
	}
	entry := gCfg.Local[pos]

	// 3. Generate (honors --min-ttl and --no-reuse).
	pin, _, gerr := genCode(entry)
	if gerr != nil {
		sudoBlocked(l, op, "totp_generation_failed")
		return nil, &sudoExit{1, gerr.Error()}
	}

	// 4. Durable `emitted`: acc is about to release the pair.
	emitted := op.rec(phaseEmitted, "credentials_emitted", "")
	if err := l.append(emitted); err != nil {
		return nil, auditFail(err)
	}

	// 5. Delivery per policy.
	if err := deliverAfterAppend(l, emitted.RecordID); err != nil {
		sudoBlocked(l, op, "audit_delivery_failed")
		return nil, auditFail(err)
	}

	// 6. Event-ID file for a deployment wrapper.
	if ac.EventIDFile != "" {
		if err := writeFileAtomic(ac.EventIDFile, []byte(op.EventID+"\n"), ""); err != nil {
			sudoBlocked(l, op, "event_id_file_failed")
			return nil, auditFail(err)
		}
	}

	return []byte(entry.Password + "\n" + pin + "\n"), nil
}

// ---------------------------------------------------------------------------
// Config-change events
// ---------------------------------------------------------------------------

// pendingCfgAudit is the in-flight config-change audit, completed by
// WriteConfig: applied() after a successful atomic save, failed() just before
// it exits on a failed one.
var pendingCfgAudit *configAudit

type configAudit struct {
	l  *auditLogger
	op *auditOp
}

// beginConfigAudit appends the `requested` record before the mutation; if the
// append fails the mutation must not happen (it exits 1).
func beginConfigAudit(ac *auditConfig, action string, item ACConfigItem) {
	l := newAuditLogger(ac)
	op := newAuditOp(auditKindConfig, ac)
	op.base.Change = &auditChange{Action: action, Reason: ac.Reason, Issue: ac.Issue}
	op.setTarget(item)
	if err := l.append(op.rec(phaseRequested, "requested", "")); err != nil {
		auditFatal(err)
	}
	pendingCfgAudit = &configAudit{l: l, op: op}
}

func (c *configAudit) failed() {
	sudoBlocked(c.l, c.op, "config_write_failed")
}

// applied records the final phase after the config was saved. The config is
// never rolled back for an audit problem: a failure leaves a pending record
// and a warning.
func (c *configAudit) applied() {
	rec := c.op.rec(phaseApplied, "applied", "")
	if err := c.l.append(rec); err != nil {
		auditWarn("config change applied but the audit record could not be written: %s", err)
		return
	}
	if c.l.cfg.sinkConfigured() {
		if res, err := c.l.ship(auditClientFactory(), true, ""); err != nil {
			auditWarn("%s", err)
		} else if !res.Reached {
			auditWarn("delivery to the audit sink is incomplete (%s); %d record(s) remain pending - retry with --audit-flush", res.Outcome, res.Pending)
		}
	}
}
