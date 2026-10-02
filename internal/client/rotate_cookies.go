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
// RotateCookies return 401 even though SID / __Secure-1PSID still work.
var gaiaTimestampCookies = map[string]struct{}{
	"__Secure-1PSIDTS": {},
	"__Secure-3PSIDTS": {},
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
// the account cookies, including a second attempt that omitted the PSIDTS
// pair. Callers keep the Messages connection up: this refusal is not itself
// a disconnect. A later Messages 401 still falls through to Chrome import or
// a re-pair when rotation cannot mint new cookies.
var ErrGaiaCookiesRejected = errors.New("google rejected the session cookies")

// GaiaRotateError is a RotateCookies failure with enough context to tell a
// bad request from a dead session. Cookie values and response bodies are
// never included: a 401 body can echo material from the request.
type GaiaRotateError struct {
	Status        int
	Sent          []string
	Received      []string
	Dropped       []string
	ContentType   string
	BodyLen       int
	OmittedPSIDTS bool
	Err           error
}

func (e *GaiaRotateError) Error() string {
	if e == nil {
		return "rotate google cookies"
	}
	base := "rotate google cookies"
	if e.Err != nil {
		base = e.Err.Error()
	}
	msg := fmt.Sprintf("%s: status=%d sent=%s received=%s content_type=%q body_len=%d omitted_psidts=%t",
		base, e.Status, strings.Join(e.Sent, ","), strings.Join(e.Received, ","), e.ContentType, e.BodyLen, e.OmittedPSIDTS)
	if len(e.Dropped) > 0 {
		msg += " dropped=" + strings.Join(e.Dropped, ",")
	}
	return msg
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
		ev = ev.Int("status", details.Status).
			Strs("sent_cookies", details.Sent).
			Strs("received_cookies", details.Received).
			Str("content_type", details.ContentType).
			Int("body_len", details.BodyLen).
			Bool("omitted_psidts", details.OmittedPSIDTS)
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
	// Gemini-API and notebooklm-py POST this exact body with Content-Type
	// application/json and Origin https://accounts.google.com. They do not
	// send Authorization, SAPISIDHASH, or X-Goog-AuthUser. The user agent is
	// libgm's Chrome string; those clients succeed with their own HTTP
	// client's default agent, so a desktop-vs-Android UA is not what makes
	// Google return 401.
	first, err := postGaiaRotate(ctx, auth, doer, nil)
	if err != nil {
		return GaiaRotateResult{}, err
	}
	// A copied PSIDTS goes stale when the browser that minted it keeps
	// calling RotateCookies. Google then rejects this POST while Messages
	// still accepts SID and __Secure-1PSID. One retry without the timestamp
	// cookies distinguishes that from a dead session.
	if first.status == http.StatusUnauthorized && sentTimestampCookie(first.sent) {
		second, err := postGaiaRotate(ctx, auth, doer, gaiaTimestampCookies)
		if err != nil {
			return GaiaRotateResult{}, err
		}
		if second.status >= 200 && second.status < 300 {
			return finishGaiaRotate(auth, second), nil
		}
		return GaiaRotateResult{}, rotateFailure(second)
	}
	if first.status < 200 || first.status >= 300 {
		return GaiaRotateResult{}, rotateFailure(first)
	}
	return finishGaiaRotate(auth, first), nil
}

type gaiaHTTPResult struct {
	status        int
	header        http.Header
	body          []byte
	sent          []string
	dropped       []string
	omittedPSIDTS bool
}

func postGaiaRotate(ctx context.Context, auth *libgm.AuthData, doer HTTPDoer, omit map[string]struct{}) (gaiaHTTPResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, RotateCookiesURL, strings.NewReader(rotateCookiesBody))
	if err != nil {
		return gaiaHTTPResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://accounts.google.com")
	req.Header.Set("User-Agent", util.UserAgent)
	sent, dropped := attachGaiaRotateCookies(req, auth, omit)
	resp, err := doer.Do(req)
	if err != nil {
		return gaiaHTTPResult{}, fmt.Errorf("rotate google cookies: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return gaiaHTTPResult{}, fmt.Errorf("rotate google cookies: %w", err)
	}
	header := resp.Header.Clone()
	return gaiaHTTPResult{
		status:        resp.StatusCode,
		header:        header,
		body:          body,
		sent:          sent,
		dropped:       dropped,
		omittedPSIDTS: omit != nil,
	}, nil
}

func finishGaiaRotate(auth *libgm.AuthData, res gaiaHTTPResult) GaiaRotateResult {
	changed := applyRotateCookies(auth, &http.Response{Header: res.header})
	wait := rotationWait(parseRotateInterval(res.body))
	noteGaiaRotateSuccess(time.Now(), wait, len(changed) > 0)
	return GaiaRotateResult{UpdatedNames: changed, NextWait: wait}
}

func rotateFailure(res gaiaHTTPResult) error {
	cause := error(ErrGaiaCookiesRejected)
	if res.status != http.StatusUnauthorized && res.status != http.StatusForbidden {
		cause = fmt.Errorf("rotate google cookies: HTTP %d", res.status)
	}
	contentType := ""
	if res.header != nil {
		contentType = res.header.Get("Content-Type")
	}
	return &GaiaRotateError{
		Status:        res.status,
		Sent:          res.sent,
		Received:      responseCookieNames(res.header),
		Dropped:       res.dropped,
		ContentType:   contentType,
		BodyLen:       len(res.body),
		OmittedPSIDTS: res.omittedPSIDTS,
		Err:           cause,
	}
}

func attachGaiaRotateCookies(req *http.Request, auth *libgm.AuthData, omit map[string]struct{}) (sent, dropped []string) {
	if auth == nil {
		return nil, nil
	}
	auth.CookiesLock.RLock()
	defer auth.CookiesLock.RUnlock()
	names := make([]string, 0, len(gaiaAccountsCookieAllow))
	for name := range auth.Cookies {
		if _, ok := gaiaAccountsCookieAllow[name]; !ok {
			continue
		}
		if _, skip := omit[name]; skip {
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

func sentTimestampCookie(sent []string) bool {
	for _, name := range sent {
		if _, ok := gaiaTimestampCookies[name]; ok {
			return true
		}
	}
	return false
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
