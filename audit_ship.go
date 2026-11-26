package main

// HTTPS shipping of audit records.
//
// Each pending record is POSTed in append order as a JSON event or a native
// Loki push. The durable cursor advances only after a 2xx. A failure stops the
// flush at that record - nothing is ever skipped or dropped. Error text never
// includes the URL, token, or any response body.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	deliveryAccepted    = "accepted"
	deliveryPending     = "pending"
	deliveryRetryable   = "retryable_error"
	deliveryConfigError = "config_error"
)

// newAuditHTTPClient builds the sink client: no redirects (they could leak the
// bearer token or hide the real destination), bounded response headers.
func newAuditHTTPClient() *http.Client {
	tr := &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		MaxResponseHeaderBytes: 16 << 10,
		TLSHandshakeTimeout:    10 * time.Second,
		DisableKeepAlives:      true,
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// loadAuditToken reads the bearer token file: regular, non-symlink, 0600; one
// trailing newline trimmed. Returns "" when no token file is configured.
func loadAuditToken(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	f, err := openAuditFile(path, os.O_RDONLY)
	if err != nil {
		return "", errors.New("audit token file is not usable (must be a regular, non-symlink 0600 file)")
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 8<<10))
	if err != nil {
		return "", errors.New("audit token file could not be read")
	}
	tok := strings.TrimSuffix(string(b), "\n")
	if tok == "" {
		return "", errors.New("audit token file is empty")
	}
	for i := 0; i < len(tok); i++ {
		if tok[i] <= 0x20 || tok[i] >= 0x7f {
			return "", errors.New("audit token file contains characters not allowed in a bearer token")
		}
	}
	return tok, nil
}

type lokiPush struct {
	Streams []lokiStream `json:"streams"`
}

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

func encodeLokiRecord(body []byte) ([]byte, error) {
	var rec struct {
		OccurredAt  string `json:"occurred_at"`
		Kind        string `json:"kind"`
		Workstation struct {
			Hostname string `json:"hostname"`
		} `json:"workstation"`
	}
	if err := json.Unmarshal(body, &rec); err != nil || rec.Kind == "" {
		return nil, errors.New("audit record cannot be encoded for Loki")
	}
	at, err := time.Parse(time.RFC3339Nano, rec.OccurredAt)
	if err != nil {
		return nil, errors.New("audit record has an invalid timestamp for Loki")
	}
	hostname := rec.Workstation.Hostname
	if hostname == "" {
		hostname = "unknown"
	}
	payload := lokiPush{Streams: []lokiStream{{
		Stream: map[string]string{"job": "acc", "kind": rec.Kind, "workstation": hostname},
		Values: [][2]string{{strconv.FormatInt(at.UnixNano(), 10), string(body)}},
	}}}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.New("audit record cannot be encoded for Loki")
	}
	return encoded, nil
}

// postAuditRecord sends one record and classifies the outcome.
func postAuditRecord(ctx context.Context, client *http.Client, sink, format, token, recordID string, body []byte) string {
	if format == auditSinkLoki {
		var err error
		body, err = encodeLokiRecord(body)
		if err != nil {
			return deliveryConfigError
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sink, bytes.NewReader(body))
	if err != nil {
		return deliveryConfigError
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Idempotency-Key", recordID)
	req.Header.Set("X-Acc-Audit-Record-Id", recordID)
	req.Header.Set("User-Agent", "acc-audit/1")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return deliveryRetryable // network error / timeout
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return deliveryAccepted
	case resp.StatusCode == http.StatusRequestTimeout, resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
		return deliveryRetryable
	default:
		return deliveryConfigError // other 4xx, 3xx: receiver/config problem
	}
}

type shipResult struct {
	Outcome string // accepted, retryable_error, config_error
	Pending int    // records still pending after this attempt
	Reached bool   // every record through upTo (or all, if upTo is "") accepted
}

// ship delivers pending records in order. total selects the budget model:
// true = Timeout is one budget for the whole call (--sudo-pipe), false =
// Timeout applies per HTTP request (--audit-flush). upToID, if set, stops once
// that record is accepted. A non-nil error means a local failure (lock, log
// integrity, cursor write) - the caller must treat it as fatal for the
// credential release.
func (l *auditLogger) ship(client *http.Client, total bool, upToID string) (shipResult, error) {
	res := shipResult{Outcome: deliveryAccepted}
	if !l.cfg.sinkConfigured() {
		return res, errors.New("no audit sink configured")
	}
	st, err := l.open(false)
	if err != nil {
		return res, err
	}
	if st == nil {
		res.Reached = true
		return res, nil
	}
	defer st.close()

	cur := st.cur
	pend := st.scan.pendingFrom(cur.Offset)
	var upToEnd int64
	if upToID != "" {
		for _, r := range st.scan.recs {
			if r.id == upToID {
				upToEnd = r.end
			}
		}
		if upToEnd == 0 {
			return res, errors.New("audit log is missing the record being delivered")
		}
	}
	finish := func(outcome string) (shipResult, error) {
		res.Outcome = outcome
		res.Pending = len(st.scan.pendingFrom(cur.Offset))
		if upToID == "" {
			res.Reached = res.Pending == 0
		} else {
			res.Reached = cur.Offset >= upToEnd
		}
		return res, nil
	}
	if len(pend) == 0 {
		return finish(deliveryAccepted)
	}

	record := func(outcome string) {
		cur.LastDelivery = outcome
		cur.LastDeliveryAt = time.Now().UTC().Format(time.RFC3339)
		_ = writeCursorQuiet(l.cfg.cursorPath(), cur) // status metadata only
	}

	token, terr := loadAuditToken(l.cfg.TokenFile)
	if terr != nil {
		record(deliveryConfigError)
		return finish(deliveryConfigError)
	}

	deadline := time.Now().Add(l.cfg.Timeout)
	for _, r := range pend {
		budget := l.cfg.Timeout
		if total {
			budget = time.Until(deadline)
			if budget <= 0 {
				record(deliveryRetryable)
				return finish(deliveryRetryable)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		body := st.data[r.start : r.end-1] // exact record, without the newline
		out := postAuditRecord(ctx, client, l.cfg.SinkURL, l.cfg.resolvedSinkFormat(), token, r.id, body)
		cancel()
		if out != deliveryAccepted {
			record(out)
			return finish(out)
		}
		cur.Offset = r.end
		cur.LastDelivery = deliveryAccepted
		cur.LastDeliveryAt = time.Now().UTC().Format(time.RFC3339)
		if err := writeCursor(l.cfg.cursorPath(), cur); err != nil {
			// The sink accepted the record but the cursor did not advance: it
			// stays pending and will be resent with the same record_id.
			return res, err
		}
		if upToID != "" && cur.Offset >= upToEnd {
			break
		}
	}
	return finish(deliveryAccepted)
}

func writeCursorQuiet(path string, c auditCursor) error {
	return writeFileAtomic(path, encodeCursor(c), "")
}
