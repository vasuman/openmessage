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

	"go.mau.fi/mautrix-gmessages/pkg/libgm"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/util"
)

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

// ErrGaiaCookiesRejected means accounts.google.com refused the stored
// cookies. The long-lived SID/SAPISID pair is no longer accepted, so a
// re-pair (or the Chrome cookie import) is the remaining recovery.
var ErrGaiaCookiesRejected = errors.New("google rejected the session cookies")

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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, RotateCookiesURL, strings.NewReader(rotateCookiesBody))
	if err != nil {
		return GaiaRotateResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://accounts.google.com")
	req.Header.Set("User-Agent", util.UserAgent)
	auth.AddCookiesToRequest(req)
	// AddCookiesToRequest stamps a Messages SAPISIDHASH. RotateCookies does
	// not use that header, and sending the wrong origin hash is not part of
	// the browser request.
	req.Header.Del("Authorization")

	resp, err := doer.Do(req)
	if err != nil {
		return GaiaRotateResult{}, fmt.Errorf("rotate google cookies: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return GaiaRotateResult{}, fmt.Errorf("rotate google cookies: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return GaiaRotateResult{}, ErrGaiaCookiesRejected
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return GaiaRotateResult{}, fmt.Errorf("rotate google cookies: HTTP %d", resp.StatusCode)
	}

	changed := applyRotateCookies(auth, resp)
	wait := rotationWait(parseRotateInterval(body))
	noteGaiaRotateSuccess(time.Now(), wait, len(changed) > 0)
	return GaiaRotateResult{UpdatedNames: changed, NextWait: wait}, nil
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
