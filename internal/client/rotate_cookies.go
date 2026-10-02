package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/mautrix-gmessages/pkg/libgm"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/util"
)

// gaiaAccountsCookieAllow is the .google.com identity set Chrome attaches to
// accounts.google.com. Pairing stores a flat copy of the messages.google.com
// Cookie header, and the Chrome import can prefer a messages-host OSID over
// the account one. Those host cookies are not in scope here. Working
// RotateCookies clients (Gemini-API, notebooklm-py) authenticate with the
// account cookies; __Secure-1PSID is the one they require, and the PSIDTS
// pair is optional input — it is what this call mints.
var gaiaAccountsCookieAllow = map[string]struct{}{
	"SID":               {},
	"HSID":              {},
	"SSID":              {},
	"APISID":            {},
	"SAPISID":           {},
	"__Secure-1PAPISID": {},
	"__Secure-3PAPISID": {},
	"__Secure-1PSID":    {},
	"__Secure-3PSID":    {},
	"__Secure-1PSIDTS":  {},
	"__Secure-3PSIDTS":  {},
	"__Secure-1PSIDCC":  {},
	"__Secure-3PSIDCC":  {},
	"SIDCC":             {},
	"NID":               {},
	"ACCOUNT_CHOOSER":   {},
}

// gaiaTimestampCookies are the short-lived cookies a still-open browser
// rotates out from under a copied session. Sending the stale pair can make
// RotateCookies refuse the call even though SID / __Secure-1PSID still work.
var gaiaTimestampCookies = map[string]struct{}{
	"__Secure-1PSIDTS": {},
	"__Secure-3PSIDTS": {},
}

// gaiaPSIDPairAllow is the cookie set measured to rotate __Secure-1PSIDTS.
// gemini-web2api-go found that sending anything beyond this pair returns 401.
// Gemini-API likewise treats __Secure-1PSID as the required input and PSIDTS
// as optional.
var gaiaPSIDPairAllow = map[string]struct{}{
	"__Secure-1PSID":   {},
	"__Secure-1PSIDTS": {},
}

var gaiaPSIDOnlyAllow = map[string]struct{}{
	"__Secure-1PSID": {},
}

// gaiaAccountStableAllow is the long-lived .google.com identity set. SIDCC,
// NID, and the *PSIDCC / *PSIDTS cookies rotate and are left off: a stale
// copy of those is a plausible reason for a refusal.
var gaiaAccountStableAllow = map[string]struct{}{
	"SID":               {},
	"HSID":              {},
	"SSID":              {},
	"APISID":            {},
	"SAPISID":           {},
	"__Secure-1PAPISID": {},
	"__Secure-3PAPISID": {},
	"__Secure-1PSID":    {},
	"__Secure-3PSID":    {},
}

// gaiaBrowserFetchHeaders is the same-origin fetch metadata Chrome attaches
// to the RotateCookies XHR. It is not part of the minimal request Gemini-API
// and notebooklm-py use successfully, so it is only a later attempt. Sec-CH-UA
// is intentionally absent: those values claim a Chrome TLS fingerprint this
// process does not have, and a mismatch is itself a common 403.
var gaiaBrowserFetchHeaders = map[string]string{
	"Referer":        "https://accounts.google.com/",
	"Sec-Fetch-Dest": "empty",
	"Sec-Fetch-Mode": "cors",
	"Sec-Fetch-Site": "same-origin",
}

const (
	// RotateCookiesURL is the accounts.google.com endpoint a signed-in browser
	// calls to mint a fresh __Secure-1PSIDTS / __Secure-3PSIDTS pair. libgm
	// applies Set-Cookie on Messages responses, but those responses do not
	// refresh PSIDTS. Nothing else in libgm calls this endpoint.
	RotateCookiesURL = "https://accounts.google.com/RotateCookies"

	// rotateCookiesBody is the jspb sentinel the web client posts. The leading
	// zeros are significant; a normal JSON number here is rejected.
	rotateCookiesBody = `[000,"-0000000000000000000"]`

	// DefaultGaiaRotateInterval is how often to refresh when RotateCookies
	// does not name a next interval. Google's response usually carries
	// ["identity.hfcr", 600] (ten minutes). Sessions that never refresh start
	// failing pings and long-polls after roughly thirty minutes.
	DefaultGaiaRotateInterval = 10 * time.Minute

	// GaiaRotateTimeout bounds one RotateCookies attempt.
	GaiaRotateTimeout = 20 * time.Second

	// minGaiaRotateGap stops a reconnect storm from posting RotateCookies on
	// every failure. Google answers a burst with 429 and that does not help
	// the session.
	minGaiaRotateGap = time.Minute

	// GaiaRotateRecentWindow is how long a successful rotation still explains
	// an in-flight request that was signed with the previous PSIDTS.
	GaiaRotateRecentWindow = 2 * time.Minute
)

// ErrGaiaCookiesUnavailable means this session has no Google-account cookies
// (a QR session, or a pair that has not stored cookies yet). Callers skip
// rotation.
var ErrGaiaCookiesUnavailable = errors.New("google session has no account cookies")

// ErrGaiaCookiesRejected means accounts.google.com returned 401 or 403 for
// every cookie and header variant. Callers keep the Messages connection up:
// this refusal is not itself a disconnect. A later Messages 401 still falls
// through to Chrome import or a re-pair when rotation cannot mint new cookies.
var ErrGaiaCookiesRejected = errors.New("google rejected the session cookies")

// GaiaRotateAttempt is one RotateCookies POST. Names and counts only.
type GaiaRotateAttempt struct {
	Variant         string
	Status          int
	Sent            []string
	Received        []string
	Dropped         []string
	ContentType     string
	BodyLen         int
	ResponseHeaders []string
}

// GaiaRotateError is a RotateCookies failure with enough context to tell a
// bad request from a dead session. Cookie values, header values, and response
// bodies are never included.
//
// Status, Sent, and the other singular fields describe the last attempt.
// Attempts and the error string's trace list every try, with content-type
// and body length ahead of the cookie names so a truncated log line still
// shows the refusal and the retries.
type GaiaRotateError struct {
	Status          int
	Sent            []string
	Received        []string
	Dropped         []string
	ContentType     string
	BodyLen         int
	OmittedPSIDTS   bool
	ResponseHeaders []string
	Attempts        []GaiaRotateAttempt
	Err             error
}

func (e *GaiaRotateError) Error() string {
	if e == nil {
		return "rotate google cookies"
	}
	base := "rotate google cookies"
	if e.Err != nil {
		base = e.Err.Error()
	}
	tries := len(e.Attempts)
	if tries == 0 {
		tries = 1
	}
	msg := fmt.Sprintf("%s: tries=%d trace=%s last_status=%d content_type=%q body_len=%d sent_count=%d sent=%s received=%s",
		base, tries, e.attemptTrace(), e.Status, e.ContentType, e.BodyLen, len(e.Sent), strings.Join(e.Sent, ","), strings.Join(e.Received, ","))
	if len(e.Dropped) > 0 {
		msg += " dropped=" + strings.Join(e.Dropped, ",")
	}
	if len(e.ResponseHeaders) > 0 {
		msg += " response_headers=" + strings.Join(e.ResponseHeaders, ",")
	}
	return msg
}

func (e *GaiaRotateError) attemptTrace() string {
	if e == nil {
		return ""
	}
	if len(e.Attempts) == 0 {
		return fmt.Sprintf("request:%d:%d", e.Status, len(e.Sent))
	}
	parts := make([]string, len(e.Attempts))
	for i, attempt := range e.Attempts {
		parts[i] = fmt.Sprintf("%s:%d:%d", attempt.Variant, attempt.Status, len(attempt.Sent))
	}
	return strings.Join(parts, ",")
}

func (e *GaiaRotateError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// AnnotateGaiaRotateLog adds the safe RotateCookies failure fields to ev.
// It also attaches err. Values are not logged.
func AnnotateGaiaRotateLog(ev *zerolog.Event, err error) *zerolog.Event {
	if ev == nil {
		return nil
	}
	var details *GaiaRotateError
	if errors.As(err, &details) && details != nil {
		tries := len(details.Attempts)
		if tries == 0 {
			tries = 1
		}
		ev = ev.Int("tries", tries).
			Str("trace", details.attemptTrace()).
			Int("status", details.Status).
			Int("last_status", details.Status).
			Str("content_type", details.ContentType).
			Int("body_len", details.BodyLen).
			Int("sent_count", len(details.Sent)).
			Strs("sent_cookies", details.Sent).
			Strs("received_cookies", details.Received).
			Bool("omitted_psidts", details.OmittedPSIDTS)
		if len(details.ResponseHeaders) > 0 {
			ev = ev.Strs("response_headers", details.ResponseHeaders)
		}
		if len(details.Dropped) > 0 {
			ev = ev.Strs("dropped_cookies", details.Dropped)
		}
	}
	return ev.Err(err)
}

// HTTPDoer is the subset of http.Client RotateGaiaCookies needs. Tests pass
// a server-bound client; production uses gaiaRotateHTTPClient.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// GaiaRotateResult is the outcome of one RotateCookies attempt.
// UpdatedNames lists cookie names whose values changed. Values are never
// included.
type GaiaRotateResult struct {
	UpdatedNames []string
	NextWait     time.Duration
	Throttled    bool
}

var gaiaRotateHTTPClient = &http.Client{
	Timeout: GaiaRotateTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		// A redirect to the login page would drop the Set-Cookie we need and
		// can land on an HTML body. Keep the RotateCookies response itself.
		return http.ErrUseLastResponse
	},
}

var (
	gaiaRotateMu        sync.Mutex
	gaiaRotateNext      time.Time
	gaiaRotateChangedAt time.Time
)

// HasGaiaAccountCookies reports whether auth carries the long-lived Google
// account cookies a RotateCookies call can refresh. QR sessions and empty
// auth data do not.
func HasGaiaAccountCookies(auth *libgm.AuthData) bool {
	if auth == nil {
		return false
	}
	auth.CookiesLock.RLock()
	defer auth.CookiesLock.RUnlock()
	if len(auth.Cookies) == 0 {
		return false
	}
	_, sid := auth.Cookies["SID"]
	_, sapisid := auth.Cookies["SAPISID"]
	_, psid := auth.Cookies["__Secure-1PSID"]
	return sid || sapisid || psid
}

// GaiaCookiesRotatedRecently reports whether a rotation that changed cookie
// values completed within within. An in-flight long-poll signed with the
// previous PSIDTS can 401 immediately after a successful rotation; that 401
// is recovered by reconnecting, not by declaring the session dead.
func GaiaCookiesRotatedRecently(within time.Duration) bool {
	if within <= 0 {
		return false
	}
	gaiaRotateMu.Lock()
	defer gaiaRotateMu.Unlock()
	return !gaiaRotateChangedAt.IsZero() && time.Since(gaiaRotateChangedAt) <= within
}

// ResetGaiaCookieRotationState clears the process-wide rotation throttle.
// Tests call it so cases do not rate-limit each other.
func ResetGaiaCookieRotationState() {
	gaiaRotateMu.Lock()
	gaiaRotateNext = time.Time{}
	gaiaRotateChangedAt = time.Time{}
	gaiaRotateMu.Unlock()
}

// NoteGaiaCookieRotationForTest records a successful rotation at changedAt
// without contacting Google.
func NoteGaiaCookieRotationForTest(changedAt time.Time) {
	gaiaRotateMu.Lock()
	gaiaRotateChangedAt = changedAt
	gaiaRotateMu.Unlock()
}

// RotateGaiaCookies posts the stored account cookies to RotateCookies and
// applies the response Set-Cookie values onto auth. It does not log cookie
// values. A nil doer uses the package client, which does not follow redirects.
func RotateGaiaCookies(ctx context.Context, auth *libgm.AuthData, doer HTTPDoer) (GaiaRotateResult, error) {
	if !HasGaiaAccountCookies(auth) {
		return GaiaRotateResult{}, ErrGaiaCookiesUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now()
	if wait, ok := claimGaiaRotate(now); !ok {
		return GaiaRotateResult{Throttled: true, NextWait: wait}, nil
	}

	if doer == nil {
		doer = gaiaRotateHTTPClient
	}
	// 401 means the cookies were not accepted. 403 is the same outcome for
	// this endpoint: gemini-web2api-go treats both as a refused rotation
	// (often a Chrome device-bound session, or a cookie set it measured as
	// too wide). Neither is a transport error, and both get the fallbacks.
	var attempts []GaiaRotateAttempt
	for _, variant := range planGaiaRotateVariants(auth) {
		res, err := postGaiaRotate(ctx, auth, doer, variant)
		if err != nil {
			if len(attempts) == 0 {
				return GaiaRotateResult{}, err
			}
			return GaiaRotateResult{}, rotateFailure(attempts, err)
		}
		attempts = append(attempts, rotateAttempt(variant.name, res))
		if res.status >= 200 && res.status < 300 {
			return finishGaiaRotate(auth, res), nil
		}
		if !gaiaAuthRefusal(res.status) {
			return GaiaRotateResult{}, rotateFailure(attempts, nil)
		}
	}
	return GaiaRotateResult{}, rotateFailure(attempts, nil)
}

// gaiaAuthRefusal reports whether status is an authentication-style rejection
// worth retrying with a narrower cookie set. 401 and 403 are both that for
// RotateCookies. 429 and 5xx are not: another cookie set will not help.
func gaiaAuthRefusal(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

type gaiaRotateVariant struct {
	name   string
	allow  map[string]struct{}
	extras map[string]string
}

// planGaiaRotateVariants is a bounded sequence. The first request is the
// pair working clients rotate with. A 401/403 then drops the timestamp
// cookie, then tries the long-lived account cookies with browser fetch
// metadata. Identical cookie sets are not repeated.
func planGaiaRotateVariants(auth *libgm.AuthData) []gaiaRotateVariant {
	stored := storedGaiaCookieNames(auth)
	candidates := []gaiaRotateVariant{
		{name: "psid_pair", allow: gaiaPSIDPairAllow},
		{name: "psid_only", allow: gaiaPSIDOnlyAllow},
		{name: "account", allow: gaiaAccountStableAllow, extras: gaiaBrowserFetchHeaders},
	}
	var planned []gaiaRotateVariant
	seen := map[string]struct{}{}
	for _, variant := range candidates {
		names := variantCookieNames(stored, variant.allow)
		if len(names) == 0 {
			continue
		}
		// A timestamp cookie alone is not a session. The PSID variants exist
		// to present __Secure-1PSID, with or without its timestamp partner.
		if (variant.name == "psid_pair" || variant.name == "psid_only") && !containsString(names, "__Secure-1PSID") {
			continue
		}
		key := strings.Join(names, ",")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		planned = append(planned, variant)
	}
	return planned
}

func storedGaiaCookieNames(auth *libgm.AuthData) map[string]struct{} {
	names := map[string]struct{}{}
	if auth == nil {
		return names
	}
	auth.CookiesLock.RLock()
	defer auth.CookiesLock.RUnlock()
	for name := range auth.Cookies {
		if _, ok := gaiaAccountsCookieAllow[name]; ok {
			names[name] = struct{}{}
		}
	}
	return names
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func variantCookieNames(stored, allow map[string]struct{}) []string {
	var names []string
	for name := range stored {
		if _, ok := allow[name]; ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

type gaiaHTTPResult struct {
	status  int
	header  http.Header
	body    []byte
	sent    []string
	dropped []string
}

func postGaiaRotate(ctx context.Context, auth *libgm.AuthData, doer HTTPDoer, variant gaiaRotateVariant) (gaiaHTTPResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, RotateCookiesURL, strings.NewReader(rotateCookiesBody))
	if err != nil {
		return gaiaHTTPResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://accounts.google.com")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", util.UserAgent)
	for name, value := range variant.extras {
		req.Header.Set(name, value)
	}
	sent, dropped := attachGaiaRotateCookies(req, auth, variant.allow)
	resp, err := doer.Do(req)
	if err != nil {
		return gaiaHTTPResult{}, fmt.Errorf("rotate google cookies: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return gaiaHTTPResult{}, fmt.Errorf("rotate google cookies: %w", err)
	}
	return gaiaHTTPResult{
		status:  resp.StatusCode,
		header:  resp.Header.Clone(),
		body:    body,
		sent:    sent,
		dropped: dropped,
	}, nil
}

func finishGaiaRotate(auth *libgm.AuthData, res gaiaHTTPResult) GaiaRotateResult {
	changed := applyRotateCookies(auth, &http.Response{Header: res.header})
	wait := rotationWait(parseRotateInterval(res.body))
	noteGaiaRotateSuccess(time.Now(), wait, len(changed) > 0)
	return GaiaRotateResult{UpdatedNames: changed, NextWait: wait}
}

func rotateAttempt(variant string, res gaiaHTTPResult) GaiaRotateAttempt {
	contentType := ""
	if res.header != nil {
		contentType = res.header.Get("Content-Type")
	}
	return GaiaRotateAttempt{
		Variant:         variant,
		Status:          res.status,
		Sent:            res.sent,
		Received:        responseCookieNames(res.header),
		Dropped:         res.dropped,
		ContentType:     contentType,
		BodyLen:         len(res.body),
		ResponseHeaders: responseHeaderNames(res.header),
	}
}

func rotateFailure(attempts []GaiaRotateAttempt, cause error) error {
	last := GaiaRotateAttempt{}
	if len(attempts) > 0 {
		last = attempts[len(attempts)-1]
	}
	if cause == nil {
		if gaiaAuthRefusal(last.Status) {
			cause = ErrGaiaCookiesRejected
		} else {
			cause = fmt.Errorf("rotate google cookies: HTTP %d", last.Status)
		}
	}
	return &GaiaRotateError{
		Status:          last.Status,
		Sent:            last.Sent,
		Received:        last.Received,
		Dropped:         last.Dropped,
		ContentType:     last.ContentType,
		BodyLen:         last.BodyLen,
		OmittedPSIDTS:   attemptsOmittedPSIDTS(attempts),
		ResponseHeaders: last.ResponseHeaders,
		Attempts:        attempts,
		Err:             cause,
	}
}

func attemptsOmittedPSIDTS(attempts []GaiaRotateAttempt) bool {
	sawTimestamp := false
	for _, attempt := range attempts {
		has := false
		for _, name := range attempt.Sent {
			if _, ok := gaiaTimestampCookies[name]; ok {
				has = true
				break
			}
		}
		if sawTimestamp && !has {
			return true
		}
		if has {
			sawTimestamp = true
		}
	}
	return false
}

func attachGaiaRotateCookies(req *http.Request, auth *libgm.AuthData, allow map[string]struct{}) (sent, dropped []string) {
	if auth == nil {
		return nil, nil
	}
	auth.CookiesLock.RLock()
	defer auth.CookiesLock.RUnlock()
	names := make([]string, 0, len(allow))
	for name := range auth.Cookies {
		if _, ok := allow[name]; !ok {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		value := auth.Cookies[name]
		// Go's AddCookie strips bytes that are illegal in a Cookie header
		// and still sends the remainder. A shortened value is a different
		// credential, so omit the cookie and record the name.
		if !cookieValueSendable(value) {
			dropped = append(dropped, name)
			continue
		}
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	for _, cookie := range req.Cookies() {
		sent = append(sent, cookie.Name)
	}
	sort.Strings(sent)
	return sent, dropped
}

// cookieValueSendable reports whether value would survive net/http's cookie
// header sanitizer unchanged. Empty values are omitted.
func cookieValueSendable(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b < 0x20 || b >= 0x7f || b == '"' || b == ';' || b == '\\' {
			return false
		}
	}
	return true
}

func responseHeaderNames(header http.Header) []string {
	if len(header) == 0 {
		return nil
	}
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func responseCookieNames(header http.Header) []string {
	seen := map[string]struct{}{}
	var names []string
	for _, cookie := range (&http.Response{Header: header}).Cookies() {
		if cookie == nil || cookie.Name == "" {
			continue
		}
		if _, ok := seen[cookie.Name]; ok {
			continue
		}
		seen[cookie.Name] = struct{}{}
		names = append(names, cookie.Name)
	}
	sort.Strings(names)
	return names
}

func claimGaiaRotate(now time.Time) (time.Duration, bool) {
	gaiaRotateMu.Lock()
	defer gaiaRotateMu.Unlock()
	if !gaiaRotateNext.IsZero() && now.Before(gaiaRotateNext) {
		return gaiaRotateNext.Sub(now), false
	}
	gaiaRotateNext = now.Add(minGaiaRotateGap)
	return 0, true
}

func noteGaiaRotateSuccess(now time.Time, wait time.Duration, changed bool) {
	if wait < minGaiaRotateGap {
		wait = minGaiaRotateGap
	}
	gaiaRotateMu.Lock()
	gaiaRotateNext = now.Add(wait)
	if changed {
		gaiaRotateChangedAt = now
	}
	gaiaRotateMu.Unlock()
}

func applyRotateCookies(auth *libgm.AuthData, resp *http.Response) []string {
	auth.CookiesLock.Lock()
	defer auth.CookiesLock.Unlock()
	if auth.Cookies == nil {
		auth.Cookies = map[string]string{}
	}
	before := make(map[string]string, len(auth.Cookies))
	for name, value := range auth.Cookies {
		before[name] = value
	}
	for _, cookie := range resp.Cookies() {
		if cookie == nil || cookie.Name == "" {
			continue
		}
		if cookie.MaxAge < 0 {
			delete(auth.Cookies, cookie.Name)
			continue
		}
		if cookie.Value == "" {
			continue
		}
		auth.Cookies[cookie.Name] = cookie.Value
	}
	return changedCookieNames(before, auth.Cookies)
}

func changedCookieNames(before, after map[string]string) []string {
	seen := make(map[string]struct{}, len(before)+len(after))
	var names []string
	for name, value := range after {
		seen[name] = struct{}{}
		if before[name] != value {
			names = append(names, name)
		}
	}
	for name := range before {
		if _, ok := seen[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// parseRotateInterval reads the identity.hfcr hint from a RotateCookies body.
// The body is XSSI-prefixed JSON, commonly:
//
//	)]}'
//	[["identity.hfcr",600],["di",1]]
//
// The number is seconds until the next rotation. Unrecognized bodies return 0
// so the caller uses DefaultGaiaRotateInterval.
func parseRotateInterval(body []byte) time.Duration {
	raw := bytes.TrimSpace(body)
	if bytes.HasPrefix(raw, []byte(")]}'")) {
		raw = bytes.TrimSpace(bytes.TrimPrefix(raw, []byte(")]}'")))
	}
	if len(raw) == 0 {
		return 0
	}
	var payload []any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return 0
	}
	for _, item := range payload {
		pair, ok := item.([]any)
		if !ok || len(pair) < 2 {
			continue
		}
		name, _ := pair[0].(string)
		if name != "identity.hfcr" {
			continue
		}
		seconds, ok := pair[1].(float64)
		if !ok || seconds <= 0 {
			return 0
		}
		return time.Duration(seconds * float64(time.Second))
	}
	return 0
}

func rotationWait(hint time.Duration) time.Duration {
	const (
		minWait = time.Minute
		maxWait = 20 * time.Minute
	)
	if hint <= 0 {
		return DefaultGaiaRotateInterval
	}
	// Refresh a bit before Google's advertised deadline so a slow request
	// still lands inside the window.
	wait := hint * 4 / 5
	if wait < minWait {
		wait = minWait
	}
	if wait > maxWait {
		wait = maxWait
	}
	return wait
}
