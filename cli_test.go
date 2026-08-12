package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/pschlump/htotp"
)

// accBin is the compiled CLI used by the integration tests in this file.
var accBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "acc-test-bin")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %s\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	accBin = filepath.Join(dir, "acc_test_bin")
	build := exec.Command("go", "build", "-o", accBin, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build acc binary: %s\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// runAcc runs the compiled CLI and captures stdout, stderr and the exit code.
func runAcc(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	return runAccEnv(t, nil, args...)
}

// runAccEnv runs the compiled CLI with extra environment variables. The ACC_*
// variables are always scrubbed from the inherited environment first, so a
// developer's own ACC_CFG/ACC_ENCRYPT_PW cannot leak into a test.
func runAccEnv(t *testing.T, extraEnv map[string]string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(accBin, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "ACC_CFG=") || strings.HasPrefix(kv, "ACC_ENCRYPT_PW=") {
			continue
		}
		env = append(env, kv)
	}
	for k, v := range extraEnv {
		env = append(env, k+"="+v)
	}
	cmd.Env = env

	err := cmd.Run()
	switch e := err.(type) {
	case nil:
		exitCode = 0
	case *exec.ExitError:
		exitCode = e.ExitCode()
	default:
		t.Fatalf("failed to run acc %v: %s", args, err)
	}
	return outBuf.String(), errBuf.String(), exitCode
}

// newCfgPath returns a path to a not-yet-existing config file in a temp dir.
func newCfgPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "test.cfg.json")
}

const (
	testUser   = "bob@example.com"
	testIssuer = "example.com"
	testSecret = "CKDPKQHM3RWX456R"
	testName   = "/example.com:bob@example.com"
)

// createTestEntry creates a fresh config with a single entry and returns the cfg path.
func createTestEntry(t *testing.T) string {
	t.Helper()
	cfg := newCfgPath(t)
	_, _, code := runAcc(t, "--cfg", cfg,
		"--create-update", testUser,
		"--secret", testSecret,
		"--issuer", testIssuer)
	if code != 0 {
		t.Fatalf("create-update failed with exit code %d", code)
	}
	return cfg
}

func TestCLI_FreshConfigCreated(t *testing.T) {
	cfg := newCfgPath(t)
	stdout, _, code := runAcc(t, "--cfg", cfg, "--list")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(stdout, "Warning: creating new config file") {
		t.Errorf("expected warning about new config file, got: %q", stdout)
	}

	fi, err := os.Stat(cfg)
	if err != nil {
		t.Fatalf("config file was not created: %s", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("config file permissions = %o, want 0600 (it holds secrets)", perm)
	}

	data, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != `{"ac_config_item":[]}` {
		t.Errorf("unexpected fresh config content: %s", data)
	}
}

func TestCLI_CreateUpdateAndList(t *testing.T) {
	cfg := newCfgPath(t)

	stdout, _, code := runAcc(t, "--cfg", cfg,
		"--create-update", testUser,
		"--secret", testSecret,
		"--issuer", testIssuer)
	if code != 0 {
		t.Fatalf("create-update exit code = %d", code)
	}
	if !strings.Contains(stdout, "Successfully imported "+testName) {
		t.Errorf("expected import confirmation, got: %q", stdout)
	}

	// Second call with same name is an update.
	stdout, _, code = runAcc(t, "--cfg", cfg,
		"--create-update", testUser,
		"--secret", testSecret,
		"--issuer", testIssuer)
	if code != 0 {
		t.Fatalf("second create-update exit code = %d", code)
	}
	if !strings.Contains(stdout, "Successfully updated "+testName) {
		t.Errorf("expected update confirmation, got: %q", stdout)
	}

	stdout, _, code = runAcc(t, "--cfg", cfg, "--list")
	if code != 0 {
		t.Fatalf("list exit code = %d", code)
	}
	lines := strings.Fields(stdout)
	if len(lines) != 1 || lines[0] != testName {
		t.Errorf("list output = %q, want exactly %q", stdout, testName)
	}
}

func TestCLI_CreateUpdateRequiresSecretAndIssuer(t *testing.T) {
	cfg := newCfgPath(t)

	_, stderr, code := runAcc(t, "--cfg", cfg, "--create-update", testUser, "--issuer", testIssuer)
	if code == 0 {
		t.Error("create-update without --secret should fail")
	}
	if !strings.Contains(stderr, "--secret is required") {
		t.Errorf("expected --secret error, got: %q", stderr)
	}

	_, stderr, code = runAcc(t, "--cfg", cfg, "--create-update", testUser, "--secret", testSecret)
	if code == 0 {
		t.Error("create-update without --issuer should fail")
	}
	if !strings.Contains(stderr, "--issuer is required") {
		t.Errorf("expected --issuer error, got: %q", stderr)
	}
}

var sixDigits = regexp.MustCompile(`^\d{6}$`)

func TestCLI_Get2faScript(t *testing.T) {
	cfg := createTestEntry(t)

	stdout, _, code := runAcc(t, "--cfg", cfg, "--get2fa", testName, "--is_script")
	if code != 0 {
		t.Fatalf("get2fa exit code = %d", code)
	}
	pin := strings.TrimSpace(stdout)
	if !sixDigits.MatchString(pin) {
		t.Fatalf("get2fa output = %q, want a 6-digit code", pin)
	}
	// Validate it is a real TOTP for this secret (allow 1 window of skew
	// so the test is not flaky at a 30-second boundary).
	if !htotp.CheckRfc6238TOTPKeyWithSkew(testUser, pin, testSecret, 1, 1) {
		t.Errorf("generated code %q does not validate against the secret", pin)
	}
}

func TestCLI_Get2faMatchesLibrary(t *testing.T) {
	cfg := createTestEntry(t)

	stdout, _, _ := runAcc(t, "--cfg", cfg, "--get2fa", testName, "--is_script")
	pin := strings.TrimSpace(stdout)

	// Compare against the library's own generator (same or adjacent window).
	expected := htotp.GenerateRfc6238TOTPKey(testUser, testSecret)
	if pin != expected && !htotp.CheckRfc6238TOTPKeyWithSkew(testUser, pin, testSecret, 1, 1) {
		t.Errorf("CLI generated %q, library generated %q", pin, expected)
	}
}

func TestCLI_Get2faOutputFile(t *testing.T) {
	cfg := createTestEntry(t)
	outFile := filepath.Join(t.TempDir(), "otk")

	_, _, code := runAcc(t, "--cfg", cfg, "--get2fa", testName, "--is_script", "--output", outFile)
	if code != 0 {
		t.Fatalf("get2fa --output exit code = %d", code)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("output file was not written: %s", err)
	}
	if !sixDigits.MatchString(strings.TrimSpace(string(data))) {
		t.Errorf("output file content = %q, want a 6-digit code", data)
	}
}

func TestCLI_Verify(t *testing.T) {
	cfg := createTestEntry(t)

	stdout, _, _ := runAcc(t, "--cfg", cfg, "--get2fa", testName, "--is_script")
	pin := strings.TrimSpace(stdout)

	stdout, _, code := runAcc(t, "--cfg", cfg, "--get2fa", testName, "--is_script", "--verify", pin)
	if code != 0 {
		t.Fatalf("verify exit code = %d", code)
	}
	if !strings.Contains(stdout, "Verified: "+pin) {
		t.Errorf("expected verification of %q, got: %q", pin, stdout)
	}

	// A definitely-wrong code: flip one digit of the real pin.
	var wrong string
	if pin[0] == '0' {
		wrong = "1" + pin[1:]
	} else {
		wrong = "0" + pin[1:]
	}
	stdout, _, _ = runAcc(t, "--cfg", cfg, "--get2fa", testName, "--is_script", "--verify", wrong)
	if !strings.Contains(stdout, "Failed To Verifiy") {
		t.Errorf("expected verification failure for %q, got: %q", wrong, stdout)
	}
}

func TestCLI_GetSecret(t *testing.T) {
	cfg := createTestEntry(t)

	stdout, _, code := runAcc(t, "--cfg", cfg, "--get-secret", testName)
	if code != 0 {
		t.Fatalf("get-secret exit code = %d", code)
	}
	if strings.TrimSpace(stdout) != testSecret {
		t.Errorf("get-secret = %q, want %q", strings.TrimSpace(stdout), testSecret)
	}
}

func TestCLI_Delete(t *testing.T) {
	cfg := createTestEntry(t)

	stdout, _, code := runAcc(t, "--cfg", cfg, "--delete", testName)
	if code != 0 {
		t.Fatalf("delete exit code = %d", code)
	}
	if !strings.Contains(stdout, "Successfully Deleted "+testName) {
		t.Errorf("expected delete confirmation, got: %q", stdout)
	}

	// Entry must be gone from --list ...
	stdout, _, _ = runAcc(t, "--cfg", cfg, "--list")
	if strings.Contains(stdout, testName) {
		t.Errorf("entry still listed after delete: %q", stdout)
	}

	// ... and --get2fa must fail.
	_, stderr, code := runAcc(t, "--cfg", cfg, "--get2fa", testName, "--is_script")
	if code == 0 {
		t.Error("get2fa on deleted entry should fail")
	}
	if !strings.Contains(stderr, "not found") {
		t.Errorf("expected not-found message, got: %q", stderr)
	}

	// Deleting it again reports that it is missing.
	stdout, _, _ = runAcc(t, "--cfg", cfg, "--delete", testName)
	if !strings.Contains(stdout, "Did not find") {
		t.Errorf("expected did-not-find message, got: %q", stdout)
	}
}

func TestCLI_Get2faNotFound(t *testing.T) {
	cfg := newCfgPath(t)
	_, stderr, code := runAcc(t, "--cfg", cfg, "--get2fa", "/nowhere:nobody", "--is_script")
	if code == 0 {
		t.Error("get2fa on missing entry should exit non-zero")
	}
	if !strings.Contains(stderr, "not found") {
		t.Errorf("expected not-found message, got: %q", stderr)
	}
}

func TestCLI_CreateNewSecret(t *testing.T) {
	cfg := newCfgPath(t)
	stdout, _, code := runAcc(t, "--cfg", cfg, "--create-new-secret")
	if code != 0 {
		t.Fatalf("create-new-secret exit code = %d", code)
	}
	got := lastLine(stdout)
	if !regexp.MustCompile(`^Secret: [A-Z2-7]{16}$`).MatchString(got) {
		t.Errorf("create-new-secret output = %q, want 'Secret: <16 base32 chars>'", got)
	}

	// Two calls should (overwhelmingly likely) produce different secrets.
	stdout2, _, _ := runAcc(t, "--cfg", cfg, "--create-new-secret")
	if got == lastLine(stdout2) {
		t.Error("two create-new-secret calls produced the same secret")
	}
}

// lastLine returns the last non-empty line of s, so tests tolerate the
// "Warning: creating new config file" line printed for a fresh --cfg.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func TestCLI_ImportQRCode(t *testing.T) {
	cfg := newCfgPath(t)
	qrPath := filepath.Join("test", "29129973.png")

	stdout, _, code := runAcc(t, "--cfg", cfg, "--import", qrPath)
	if code != 0 {
		t.Fatalf("import exit code = %d", code)
	}
	wantName := "/app.example.com:bob3@bob.com"
	if !strings.Contains(stdout, "Successfully imported "+wantName) {
		t.Errorf("expected import of %q, got: %q", wantName, stdout)
	}

	// The secret from the QR code must be stored.
	stdout, _, code = runAcc(t, "--cfg", cfg, "--get-secret", wantName)
	if code != 0 {
		t.Fatalf("get-secret after import exit code = %d", code)
	}
	if strings.TrimSpace(stdout) != "UCVCQIOR23Z2BJ3W" {
		t.Errorf("imported secret = %q, want %q", strings.TrimSpace(stdout), "UCVCQIOR23Z2BJ3W")
	}

	// And codes must generate for the imported entry.
	stdout, _, _ = runAcc(t, "--cfg", cfg, "--get2fa", wantName, "--is_script")
	if !sixDigits.MatchString(strings.TrimSpace(stdout)) {
		t.Errorf("get2fa for imported entry = %q, want a 6-digit code", stdout)
	}
}

func TestCLI_ImportMissingFile(t *testing.T) {
	cfg := newCfgPath(t)
	_, stderr, code := runAcc(t, "--cfg", cfg, "--import", "no-such-file.png")
	if code == 0 {
		t.Error("import of missing file should exit non-zero")
	}
	if !strings.Contains(stderr, "Unable to open/process qr image") {
		t.Errorf("expected image error message, got: %q", stderr)
	}
}

func TestCLI_ExtraArgsRejected(t *testing.T) {
	cfg := newCfgPath(t)
	_, stderr, code := runAcc(t, "--cfg", cfg, "--list", "unexpected-positional-arg")
	if code == 0 {
		t.Error("extra positional args should exit non-zero")
	}
	if !strings.Contains(stderr, "No additional argumetns") {
		t.Errorf("expected rejection message, got: %q", stderr)
	}
}

func TestCLI_Version(t *testing.T) {
	stdout, _, code := runAcc(t, "--version")
	if code != 0 {
		t.Fatalf("version exit code = %d", code)
	}
	if !strings.Contains(stdout, "Version:") {
		t.Errorf("expected version output, got: %q", stdout)
	}
}

// ---------------------------------------------------------------------------
// Tests for the automation/2FA-sudo features
// ---------------------------------------------------------------------------

func TestCLI_EnvCfgDefault(t *testing.T) {
	cfg := newCfgPath(t)
	stdout, _, code := runAccEnv(t, map[string]string{"ACC_CFG": cfg}, "--list")
	if code != 0 {
		t.Fatalf("list with ACC_CFG exit code = %d", code)
	}
	if !strings.Contains(stdout, "Warning: creating new config file: "+cfg) {
		t.Errorf("expected config creation at ACC_CFG path, got: %q", stdout)
	}
	if _, err := os.Stat(cfg); err != nil {
		t.Errorf("config file not created at ACC_CFG path: %s", err)
	}
}

func TestCLI_EncryptedRoundTrip(t *testing.T) {
	cfg := newCfgPath(t)
	env := map[string]string{"ACC_ENCRYPT_PW": "test-pw-123"}

	_, _, code := runAccEnv(t, env, "--cfg", cfg,
		"--create-update", testUser,
		"--secret", testSecret,
		"--issuer", testIssuer)
	if code != 0 {
		t.Fatalf("encrypted create-update exit code = %d", code)
	}

	// The file on disk must be encrypted: marker present, plaintext gone.
	data, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "encrypted_data") {
		t.Errorf("encrypted config missing encrypted_data field: %s", data)
	}
	if strings.Contains(string(data), testSecret) {
		t.Errorf("plaintext secret found in encrypted config: %s", data)
	}
	if strings.Contains(string(data), testUser) {
		t.Errorf("plaintext username found in encrypted config: %s", data)
	}

	// Reads work with the password from the environment ...
	stdout, _, code := runAccEnv(t, env, "--cfg", cfg, "--list")
	if code != 0 || !strings.Contains(stdout, testName) {
		t.Errorf("list with ACC_ENCRYPT_PW: code=%d out=%q", code, stdout)
	}
	stdout, _, code = runAccEnv(t, env, "--cfg", cfg, "--get2fa", testName, "--is_script")
	if code != 0 || !sixDigits.MatchString(strings.TrimSpace(stdout)) {
		t.Errorf("get2fa with ACC_ENCRYPT_PW: code=%d out=%q", code, stdout)
	}

	// ... and with the --encrypted flag ...
	stdout, _, code = runAcc(t, "--cfg", cfg, "--encrypted", "test-pw-123", "--list")
	if code != 0 || !strings.Contains(stdout, testName) {
		t.Errorf("list with --encrypted flag: code=%d out=%q", code, stdout)
	}

	// ... but fail without a password, or with the wrong one.
	_, stderr, code := runAcc(t, "--cfg", cfg, "--list")
	if code == 0 || !strings.Contains(stderr, "encrypted") {
		t.Errorf("list without password should fail: code=%d err=%q", code, stderr)
	}
	_, stderr, code = runAcc(t, "--cfg", cfg, "--encrypted", "wrong-pw", "--list")
	if code == 0 || !strings.Contains(stderr, "Unable to decrypt") {
		t.Errorf("list with wrong password should fail: code=%d err=%q", code, stderr)
	}
}

func TestCLI_SubstringMatch(t *testing.T) {
	cfg := createTestEntry(t)

	// Unique substring resolves.
	stdout, _, code := runAcc(t, "--cfg", cfg, "--get2fa", "bob@example", "--is_script")
	if code != 0 || !sixDigits.MatchString(strings.TrimSpace(stdout)) {
		t.Errorf("get2fa by substring: code=%d out=%q", code, stdout)
	}

	// Add a second entry that also matches "example.com".
	_, _, _ = runAcc(t, "--cfg", cfg,
		"--create-update", "alice@example.com",
		"--secret", "UCVCQIOR23Z2BJ3W",
		"--issuer", testIssuer)

	// Now "example.com" alone is ambiguous (matches both entries).
	_, stderr, code := runAcc(t, "--cfg", cfg, "--get2fa", "example.com", "--is_script")
	if code == 0 || !strings.Contains(stderr, "ambiguous") {
		t.Errorf("expected ambiguous error: code=%d err=%q", code, stderr)
	}

	// Exact full name still wins even when it is also a substring of nothing else.
	stdout, _, code = runAcc(t, "--cfg", cfg, "--get2fa", testName, "--is_script")
	if code != 0 || !sixDigits.MatchString(strings.TrimSpace(stdout)) {
		t.Errorf("get2fa by exact name: code=%d out=%q", code, stdout)
	}
}

func TestCLI_ShowTTL(t *testing.T) {
	cfg := createTestEntry(t)
	stdout, _, code := runAcc(t, "--cfg", cfg, "--get2fa", testName, "--is_script", "--show-ttl")
	if code != 0 {
		t.Fatalf("show-ttl exit code = %d", code)
	}
	got := strings.TrimSpace(stdout)
	if !regexp.MustCompile(`^\d{6} \d{1,2}$`).MatchString(got) {
		t.Errorf("show-ttl output = %q, want '<code> <ttl>'", got)
	}
}

func TestCLI_MinTTL(t *testing.T) {
	cfg := createTestEntry(t)
	// With --min-ttl 2 the reported TTL must be at least 2 (worst-case wait ~2s).
	stdout, _, code := runAcc(t, "--cfg", cfg, "--get2fa", testName, "--is_script", "--show-ttl", "--min-ttl", "2")
	if code != 0 {
		t.Fatalf("min-ttl exit code = %d", code)
	}
	fields := strings.Fields(strings.TrimSpace(stdout))
	if len(fields) != 2 {
		t.Fatalf("min-ttl output = %q, want '<code> <ttl>'", stdout)
	}
	var ttl int
	if _, err := fmt.Sscanf(fields[1], "%d", &ttl); err != nil || ttl < 2 {
		t.Errorf("min-ttl output = %q, want ttl >= 2", stdout)
	}
}

func TestCLI_SudoPipe(t *testing.T) {
	cfg := newCfgPath(t)
	_, _, code := runAcc(t, "--cfg", cfg,
		"--create-update", "phil",
		"--secret", testSecret,
		"--issuer", "myserver",
		"--password", "sudopw-abc")
	if code != 0 {
		t.Fatalf("create-update with password exit code = %d", code)
	}

	stdout, _, code := runAcc(t, "--cfg", cfg, "--sudo-pipe", "myserver")
	if code != 0 {
		t.Fatalf("sudo-pipe exit code = %d", code)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 {
		t.Fatalf("sudo-pipe output = %q, want exactly 2 lines", stdout)
	}
	if lines[0] != "sudopw-abc" {
		t.Errorf("sudo-pipe first line = %q, want the stored password", lines[0])
	}
	if !sixDigits.MatchString(strings.TrimSpace(lines[1])) {
		t.Errorf("sudo-pipe second line = %q, want a 6-digit code", lines[1])
	}
	// The code must validate for user "phil".
	if !htotp.CheckRfc6238TOTPKeyWithSkew("phil", strings.TrimSpace(lines[1]), testSecret, 1, 1) {
		t.Errorf("sudo-pipe code does not validate")
	}
}

func TestCLI_Enroll(t *testing.T) {
	cfg := newCfgPath(t)
	qrFile := filepath.Join(t.TempDir(), "enroll.png")

	stdout, _, code := runAcc(t, "--cfg", cfg, "--enroll", "phil", "--issuer", "myserver", "--qr", qrFile)
	if code != 0 {
		t.Fatalf("enroll exit code = %d", code)
	}
	if !strings.Contains(stdout, "Name: /myserver:phil") {
		t.Errorf("enroll output missing name: %q", stdout)
	}
	if !strings.Contains(stdout, "URI: otpauth://totp/") {
		t.Errorf("enroll output missing provisioning URI: %q", stdout)
	}

	// Entry stored and listed.
	stdout, _, _ = runAcc(t, "--cfg", cfg, "--list")
	if !strings.Contains(stdout, "/myserver:phil") {
		t.Errorf("enrolled entry not in list: %q", stdout)
	}

	// Secret is 16-char base32 and generates valid codes.
	stdout, _, _ = runAcc(t, "--cfg", cfg, "--get-secret", "/myserver:phil")
	secret := strings.TrimSpace(stdout)
	if !regexp.MustCompile(`^[A-Z2-7]{16}$`).MatchString(secret) {
		t.Errorf("enrolled secret = %q, want 16 base32 chars", secret)
	}
	stdout, _, _ = runAcc(t, "--cfg", cfg, "--get2fa", "/myserver:phil", "--is_script")
	pin := strings.TrimSpace(stdout)
	if !htotp.CheckRfc6238TOTPKeyWithSkew("phil", pin, secret, 1, 1) {
		t.Errorf("code from enrolled secret does not validate")
	}

	// QR png was written and looks like a PNG.
	data, err := os.ReadFile(qrFile)
	if err != nil {
		t.Fatalf("QR file not written: %s", err)
	}
	if len(data) < 8 || !bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
		t.Errorf("QR file is not a PNG (first bytes: %x)", data[:8])
	}
}

func TestCLI_EnrollRequiresIssuer(t *testing.T) {
	cfg := newCfgPath(t)
	_, stderr, code := runAcc(t, "--cfg", cfg, "--enroll", "phil")
	if code == 0 || !strings.Contains(stderr, "--issuer is required") {
		t.Errorf("enroll without issuer should fail: code=%d err=%q", code, stderr)
	}
}

func TestCLI_CheckTime_BadHost(t *testing.T) {
	_, stderr, code := runAcc(t, "--check-time", "no-such-host.invalid")
	if code == 0 {
		t.Error("check-time against an unresolvable host should fail")
	}
	if !strings.Contains(stderr, "Unable to get time") {
		t.Errorf("expected ssh error message, got: %q", stderr)
	}
}

func TestCLI_CheckTime(t *testing.T) {
	host := os.Getenv("ACC_TEST_SSH_HOST")
	if host == "" {
		t.Skip("set ACC_TEST_SSH_HOST to an ssh-reachable host to run this test")
	}
	stdout, _, code := runAcc(t, "--check-time", host)
	if code != 0 {
		t.Errorf("check-time %s exit code = %d, out=%q", host, code, stdout)
	}
	if !strings.Contains(stdout, "Skew:") {
		t.Errorf("expected skew report, got: %q", stdout)
	}
}
