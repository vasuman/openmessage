package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/mautrix-gmessages/pkg/libgm"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/util"
)

func TestRotateGaiaCookiesAppliesSetCookie(t *testing.T) {
	ResetGaiaCookieRotationState()
	t.Cleanup(ResetGaiaCookieRotationState)

	const rotated = "psidts-rotated"
	var (
		gotURL      string
		gotBody     string
		gotAuth     string
		gotAuthUser string
		gotOrigin   string
		gotType     string
		gotUA       string
		gotCookie   string
		gotMethod   string
		gotFetch    string
	)
	auth := libgm.NewAuthData()
	auth.SetCookies(map[string]string{
		"SID":              "sid-stable",
		"SAPISID":          "sap-stable",
		"__Secure-1PSID":   "psid-stable",
		"__Secure-1PSIDTS": "psidts-stale",
		"__Secure-3PSIDTS": "psidts3-stale",
		"NID":              "nid-stale",
		"OSID":             "messages-host-osid",
		"COMPASS":          "messages-host-compass",
	})
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		gotURL = req.URL.String()
		gotMethod = req.Method
		body, _ := io.ReadAll(req.Body)
		gotBody = string(body)
		gotAuth = req.Header.Get("Authorization")
		gotAuthUser = req.Header.Get("X-Goog-AuthUser")
		gotOrigin = req.Header.Get("Origin")
		gotType = req.Header.Get("Content-Type")
		gotUA = req.Header.Get("User-Agent")
		gotCookie = req.Header.Get("Cookie")
		gotFetch = req.Header.Get("Sec-Fetch-Site")
		header := make(http.Header)
		header.Add("Set-Cookie", "__Secure-1PSIDTS="+rotated+"; Path=/; Secure")
		header.Add("Set-Cookie", "__Secure-3PSIDTS=psidts3-rotated; Path=/; Secure")
		header.Add("Set-Cookie", "SIDCC=sidcc-rotated; Path=/; Secure")
		header.Add("Set-Cookie", "__Secure-1PSIDCC=cc1; Path=/; Secure")
		header.Add("Set-Cookie", "__Secure-3PSIDCC=cc3; Path=/; Secure")
		header.Add("Set-Cookie", "NID=; Max-Age=0")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader(")]}'\n[[\"identity.hfcr\",600],[\"di\",1]]")),
			Request:    req,
		}, nil
	})

	res, err := RotateGaiaCookies(context.Background(), auth, doer)
	if err != nil {
		t.Fatalf("RotateGaiaCookies() error = %v", err)
	}
	if gotMethod != http.MethodPost || gotURL != RotateCookiesURL {
		t.Fatalf("request = %s %s, want POST %s", gotMethod, gotURL, RotateCookiesURL)
	}
	if gotBody != rotateCookiesBody {
		t.Fatalf("body = %q, want %q", gotBody, rotateCookiesBody)
	}
	if gotAuth != "" {
		t.Fatal("RotateCookies request included an Authorization header")
	}
	if gotAuthUser != "" {
		t.Fatal("RotateCookies request included X-Goog-AuthUser")
	}
	if gotOrigin != "https://accounts.google.com" || gotType != "application/json" {
		t.Fatalf("origin/type = %q / %q", gotOrigin, gotType)
	}
	if gotUA != util.UserAgent {
		t.Fatalf("user agent = %q, want %q", gotUA, util.UserAgent)
	}
	if !strings.Contains(gotCookie, "__Secure-1PSID=psid-stable") || !strings.Contains(gotCookie, "__Secure-1PSIDTS=psidts-stale") {
		t.Fatalf("first attempt = %s, want the __Secure-1PSID pair", gotCookie)
	}
	sentNames := cookieNames(gotCookie)
	if strings.Join(sentNames, ",") != "__Secure-1PSID,__Secure-1PSIDTS" {
		t.Fatalf("first attempt cookies = %v", sentNames)
	}
	if gotFetch != "" {
		t.Fatalf("first attempt sent Sec-Fetch-Site %q", gotFetch)
	}
	if strings.Contains(errString(err), rotated) {
		t.Fatal("error included a cookie value")
	}
	auth.CookiesLock.RLock()
	got := copyMap(auth.Cookies)
	auth.CookiesLock.RUnlock()
	if got["__Secure-1PSIDTS"] != rotated || got["__Secure-3PSIDTS"] != "psidts3-rotated" {
		t.Fatalf("PSIDTS cookies = %#v", got)
	}
	if got["SIDCC"] != "sidcc-rotated" || got["__Secure-1PSIDCC"] != "cc1" || got["__Secure-3PSIDCC"] != "cc3" {
		t.Fatalf("SIDCC cookies = %#v", got)
	}
	if got["SID"] != "sid-stable" || got["SAPISID"] != "sap-stable" {
		t.Fatalf("stable cookies changed: %#v", got)
	}
	if _, exists := got["NID"]; exists {
		t.Fatalf("deleted NID survived: %#v", got)
	}
	wantNames := []string{"NID", "SIDCC", "__Secure-1PSIDCC", "__Secure-1PSIDTS", "__Secure-3PSIDCC", "__Secure-3PSIDTS"}
	if strings.Join(res.UpdatedNames, ",") != strings.Join(wantNames, ",") {
		t.Fatalf("updated names = %v, want %v", res.UpdatedNames, wantNames)
	}
	if res.NextWait != 8*time.Minute {
		t.Fatalf("next wait = %s, want 8m (80%% of the 600s hint)", res.NextWait)
	}
	if !GaiaCookiesRotatedRecently(GaiaRotateRecentWindow) {
		t.Fatal("successful rotation was not recorded")
	}
}

func TestRotateGaiaCookiesRejectionKeepsCookies(t *testing.T) {
	ResetGaiaCookieRotationState()
	t.Cleanup(ResetGaiaCookieRotationState)

	const secret = "psidts-must-not-leak"
	const body = "rejected " + secret
	auth := libgm.NewAuthData()
	auth.SetCookies(map[string]string{
		"SID":              "sid-stable",
		"SAPISID":          "sap-stable",
		"__Secure-1PSID":   "psid-stable",
		"__Secure-1PSIDTS": secret,
		"OSID":             "messages-osid-" + secret,
	})
	var cookies []string
	var fetches []string
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		cookies = append(cookies, req.Header.Get("Cookie"))
		fetches = append(fetches, req.Header.Get("Sec-Fetch-Site"))
		header := make(http.Header)
		header.Set("Content-Type", "text/html; charset=utf-8")
		header.Set("Sec-Session-Google-Challenge", secret)
		header.Add("Set-Cookie", "NID="+secret+"; Path=/")
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	})
	_, err := RotateGaiaCookies(context.Background(), auth, doer)
	if !errors.Is(err, ErrGaiaCookiesRejected) {
		t.Fatalf("error = %v, want ErrGaiaCookiesRejected", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "messages-osid") {
		t.Fatalf("rejection error included a cookie value: %v", err)
	}
	if len(cookies) != 3 {
		t.Fatalf("attempts = %d, want psid_pair, psid_only, then account", len(cookies))
	}
	if cookies[0] != "__Secure-1PSID=psid-stable; __Secure-1PSIDTS="+secret {
		t.Fatalf("first cookie header = %s", cookies[0])
	}
	if cookies[1] != "__Secure-1PSID=psid-stable" {
		t.Fatalf("second cookie header = %s", cookies[1])
	}
	if strings.Contains(cookies[2], "PSIDTS") || strings.Contains(cookies[2], "OSID=") {
		t.Fatalf("account retry = %s", cookies[2])
	}
	if !strings.Contains(cookies[2], "SID=sid-stable") || !strings.Contains(cookies[2], "SAPISID=sap-stable") {
		t.Fatalf("account retry dropped the long-lived cookies: %s", cookies[2])
	}
	if fetches[0] != "" || fetches[1] != "" || fetches[2] != "same-origin" {
		t.Fatalf("Sec-Fetch-Site by attempt = %v", fetches)
	}
	var details *GaiaRotateError
	if !errors.As(err, &details) {
		t.Fatalf("error = %T, want *GaiaRotateError", err)
	}
	if details.Status != http.StatusUnauthorized || details.ContentType != "text/html; charset=utf-8" || details.BodyLen != len(body) || !details.OmittedPSIDTS {
		t.Fatalf("details = %+v", details)
	}
	if strings.Join(details.Sent, ",") != "SAPISID,SID,__Secure-1PSID" {
		t.Fatalf("sent = %v", details.Sent)
	}
	if !strings.Contains(err.Error(), "tries=3") || !strings.Contains(err.Error(), "trace=psid_pair:401:2,psid_only:401:1,account:401:3") {
		t.Fatalf("error = %v", err)
	}
	typeAt := strings.Index(err.Error(), "content_type=")
	sentAt := strings.Index(err.Error(), " sent=")
	if typeAt < 0 || sentAt < 0 || typeAt > sentAt || !strings.Contains(err.Error(), "body_len=") || !strings.Contains(err.Error(), "sent_count=3") {
		t.Fatalf("diagnostic order = %s", err.Error())
	}
	if !strings.Contains(err.Error(), "Sec-Session-Google-Challenge") {
		t.Fatalf("response header name missing: %s", err.Error())
	}
	if strings.Join(details.Received, ",") != "NID" {
		t.Fatalf("received = %v", details.Received)
	}
	auth.CookiesLock.RLock()
	defer auth.CookiesLock.RUnlock()
	if auth.Cookies["__Secure-1PSIDTS"] != secret {
		t.Fatalf("cookie changed on rejection: %#v", auth.Cookies)
	}
}

func TestRotateGaiaCookiesHTTPFailureDoesNotApplyCookies(t *testing.T) {
	ResetGaiaCookieRotationState()
	t.Cleanup(ResetGaiaCookieRotationState)

	const secret = "psidts-body"
	auth := libgm.NewAuthData()
	auth.SetCookies(map[string]string{"SID": "sid-stable", "__Secure-1PSIDTS": "stale"})
	calls := 0
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		header := make(http.Header)
		header.Set("Content-Type", "text/plain")
		header.Add("Set-Cookie", "__Secure-1PSIDTS="+secret+"; Path=/")
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader(secret)),
			Request:    req,
		}, nil
	})
	_, err := RotateGaiaCookies(context.Background(), auth, doer)
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("error = %v, want HTTP 500", err)
	}
	if calls != 1 {
		t.Fatalf("attempts = %d, want 1 (no PSIDTS retry on HTTP 500)", calls)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error included a cookie value: %v", err)
	}
	var details *GaiaRotateError
	if !errors.As(err, &details) || details.Status != 500 || details.BodyLen != len(secret) || details.ContentType != "text/plain" {
		t.Fatalf("details = %+v", details)
	}
	auth.CookiesLock.RLock()
	defer auth.CookiesLock.RUnlock()
	if auth.Cookies["__Secure-1PSIDTS"] != "stale" {
		t.Fatalf("cookie applied from a failed response: %#v", auth.Cookies)
	}
}

func TestRotateGaiaCookiesSkipsSessionsWithoutAccountCookies(t *testing.T) {
	called := false
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("should not be called")
	})
	_, err := RotateGaiaCookies(context.Background(), libgm.NewAuthData(), doer)
	if !errors.Is(err, ErrGaiaCookiesUnavailable) {
		t.Fatalf("error = %v, want unavailable", err)
	}
	if called {
		t.Fatal("RotateCookies was called for an empty session")
	}
	if HasGaiaAccountCookies(nil) || HasGaiaAccountCookies(libgm.NewAuthData()) {
		t.Fatal("empty auth reported account cookies")
	}
}

func TestRotateGaiaCookiesThrottlesASecondAttempt(t *testing.T) {
	ResetGaiaCookieRotationState()
	t.Cleanup(ResetGaiaCookieRotationState)

	calls := 0
	auth := libgm.NewAuthData()
	auth.SetCookies(map[string]string{"SAPISID": "sap-stable", "__Secure-1PSIDTS": "stale"})
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		header := make(http.Header)
		header.Add("Set-Cookie", "__Secure-1PSIDTS=rotated; Path=/")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader("[]")),
			Request:    req,
		}, nil
	})
	if _, err := RotateGaiaCookies(context.Background(), auth, doer); err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	res, err := RotateGaiaCookies(context.Background(), auth, doer)
	if err != nil {
		t.Fatalf("second rotate: %v", err)
	}
	if calls != 1 {
		t.Fatalf("RotateCookies calls = %d, want 1", calls)
	}
	if !res.Throttled || res.NextWait <= 0 {
		t.Fatalf("second result = %+v, want throttled with a wait", res)
	}
}

func TestRotateGaiaCookiesRetriesWithoutStalePSIDTS(t *testing.T) {
	ResetGaiaCookieRotationState()
	t.Cleanup(ResetGaiaCookieRotationState)

	const secret = "psidts-stale-secret"
	auth := libgm.NewAuthData()
	auth.SetCookies(map[string]string{
		"SID":              "sid-stable",
		"__Secure-1PSID":   "psid-stable",
		"__Secure-1PSIDTS": secret,
		"__Secure-3PSIDTS": "psidts3-stale",
		"OSID":             "messages-osid",
	})
	calls := 0
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		cookie := req.Header.Get("Cookie")
		if strings.Contains(cookie, "OSID=") {
			t.Fatalf("sent OSID: %s", cookie)
		}
		header := make(http.Header)
		if calls == 1 {
			if !strings.Contains(cookie, "__Secure-1PSIDTS=") {
				t.Fatalf("first attempt omitted PSIDTS: %s", cookie)
			}
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Header:     header,
				Body:       io.NopCloser(strings.NewReader("no")),
				Request:    req,
			}, nil
		}
		if strings.Contains(cookie, "PSIDTS") {
			t.Fatalf("retry still sent a timestamp cookie: %s", cookie)
		}
		header.Add("Set-Cookie", "__Secure-1PSIDTS=psidts-fresh; Path=/; Secure")
		header.Add("Set-Cookie", "__Secure-3PSIDTS=psidts3-fresh; Path=/; Secure")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader(")]}'\n[[\"identity.hfcr\",600]]")),
			Request:    req,
		}, nil
	})
	res, err := RotateGaiaCookies(context.Background(), auth, doer)
	if err != nil {
		t.Fatalf("RotateGaiaCookies() error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("attempts = %d, want 2", calls)
	}
	auth.CookiesLock.RLock()
	got := copyMap(auth.Cookies)
	auth.CookiesLock.RUnlock()
	if got["__Secure-1PSIDTS"] != "psidts-fresh" || got["__Secure-3PSIDTS"] != "psidts3-fresh" {
		t.Fatalf("cookies = %#v", got)
	}
	if got["SID"] != "sid-stable" || got["OSID"] != "messages-osid" {
		t.Fatalf("unrelated cookies changed: %#v", got)
	}
	if strings.Join(res.UpdatedNames, ",") != "__Secure-1PSIDTS,__Secure-3PSIDTS" {
		t.Fatalf("updated = %v", res.UpdatedNames)
	}
}

func TestRotateGaiaCookies403FallsBackAndRecovers(t *testing.T) {
	ResetGaiaCookieRotationState()
	t.Cleanup(ResetGaiaCookieRotationState)

	const secret = "psidts-stale-secret"
	auth := libgm.NewAuthData()
	auth.SetCookies(map[string]string{
		"SID":              "sid-stable",
		"HSID":             "hsid-stable",
		"SSID":             "ssid-stable",
		"APISID":           "ap-stable",
		"SAPISID":          "sap-stable",
		"__Secure-1PSID":   "psid-stable",
		"__Secure-3PSID":   "psid3-stable",
		"__Secure-1PSIDTS": secret,
		"__Secure-3PSIDTS": "psidts3-stale",
		"SIDCC":            "sidcc-stale",
		"__Secure-1PSIDCC": "cc1-stale",
		"__Secure-3PSIDCC": "cc3-stale",
		"NID":              "nid-stale",
		"OSID":             "messages-osid",
	})
	var variants []string
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		cookie := req.Header.Get("Cookie")
		if strings.Contains(cookie, "OSID=") || strings.Contains(cookie, "SIDCC=") || strings.Contains(cookie, "PSIDCC=") || strings.Contains(cookie, "NID=") {
			t.Fatalf("sent a rotating or host cookie: %s", cookie)
		}
		header := make(http.Header)
		switch {
		case strings.Contains(cookie, "__Secure-1PSIDTS="):
			variants = append(variants, "psid_pair")
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Header:     header,
				Body:       io.NopCloser(strings.NewReader("no")),
				Request:    req,
			}, nil
		case cookie == "__Secure-1PSID=psid-stable":
			variants = append(variants, "psid_only")
			if req.Header.Get("Sec-Fetch-Site") != "" {
				t.Fatal("psid_only sent Sec-Fetch-Site")
			}
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Header:     header,
				Body:       io.NopCloser(strings.NewReader("no")),
				Request:    req,
			}, nil
		default:
			variants = append(variants, "account")
			if req.Header.Get("Sec-Fetch-Site") != "same-origin" || req.Header.Get("Referer") != "https://accounts.google.com/" {
				t.Fatalf("account headers origin fetch/referer = %q / %q", req.Header.Get("Sec-Fetch-Site"), req.Header.Get("Referer"))
			}
			if req.Header.Get("Authorization") != "" || req.Header.Get("X-Goog-AuthUser") != "" {
				t.Fatal("account attempt sent an auth header")
			}
			header.Add("Set-Cookie", "__Secure-1PSIDTS=psidts-fresh; Path=/; Secure")
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     header,
				Body:       io.NopCloser(strings.NewReader(")]}'\n[[\"identity.hfcr\",600]]")),
				Request:    req,
			}, nil
		}
	})
	res, err := RotateGaiaCookies(context.Background(), auth, doer)
	if err != nil {
		t.Fatalf("RotateGaiaCookies() error = %v", err)
	}
	if strings.Join(variants, ",") != "psid_pair,psid_only,account" {
		t.Fatalf("variants = %v", variants)
	}
	auth.CookiesLock.RLock()
	got := auth.Cookies["__Secure-1PSIDTS"]
	auth.CookiesLock.RUnlock()
	if got != "psidts-fresh" {
		t.Fatalf("PSIDTS = %q", got)
	}
	if strings.Join(res.UpdatedNames, ",") != "__Secure-1PSIDTS" {
		t.Fatalf("updated = %v", res.UpdatedNames)
	}
}

func TestRotateGaiaCookiesForbiddenDoesNotDropPSIDTS(t *testing.T) {
	ResetGaiaCookieRotationState()
	t.Cleanup(ResetGaiaCookieRotationState)

	auth := libgm.NewAuthData()
	auth.SetCookies(map[string]string{"SID": "sid-stable", "__Secure-1PSIDTS": "stale"})
	calls := 0
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})
	_, err := RotateGaiaCookies(context.Background(), auth, doer)
	if !errors.Is(err, ErrGaiaCookiesRejected) {
		t.Fatalf("error = %v, want rejection", err)
	}
	if calls != 1 {
		t.Fatalf("attempts = %d, want 1", calls)
	}
	var details *GaiaRotateError
	if !errors.As(err, &details) || details.OmittedPSIDTS || details.Status != http.StatusForbidden {
		t.Fatalf("details = %+v", details)
	}
}

func TestRotateGaiaCookiesReportsDroppedCookieNames(t *testing.T) {
	ResetGaiaCookieRotationState()
	t.Cleanup(ResetGaiaCookieRotationState)

	auth := libgm.NewAuthData()
	auth.SetCookies(map[string]string{
		"SID":     "sid;not-a-legal-cookie-value",
		"SAPISID": "sap-stable",
	})
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.Header.Get("Cookie"), "not-a-legal") {
			t.Fatal("illegal cookie value was sent")
		}
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("no")),
			Request:    req,
		}, nil
	})
	_, err := RotateGaiaCookies(context.Background(), auth, doer)
	var details *GaiaRotateError
	if !errors.As(err, &details) {
		t.Fatalf("error = %v", err)
	}
	if strings.Join(details.Dropped, ",") != "SID" {
		t.Fatalf("dropped = %v", details.Dropped)
	}
	if strings.Contains(err.Error(), "not-a-legal") {
		t.Fatalf("error included a cookie value: %v", err)
	}
}

func TestGaiaRotateClientDoesNotFollowRedirects(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://accounts.google.com/RotateCookies", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = gaiaRotateHTTPClient.CheckRedirect(req, nil)
	if !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect = %v, want ErrUseLastResponse", err)
	}
}

func TestPersistCookiesNowBypassesEventThrottle(t *testing.T) {
	auth := libgm.NewAuthData()
	auth.SetCookies(map[string]string{"SID": "initial", "__Secure-1PSIDTS": "stale"})
	gmClient := libgm.NewClient(auth, nil, zerolog.Nop())
	now := time.Date(2026, time.October, 2, 12, 0, 0, 0, time.UTC)
	sessionPath := filepath.Join(t.TempDir(), "session.json")
	handler := &EventHandler{
		Logger:              zerolog.Nop(),
		SessionPath:         sessionPath,
		Client:              &Client{GM: gmClient, Logger: zerolog.Nop()},
		Now:                 func() time.Time { return now },
		PersistCookiesEvery: 5 * time.Minute,
	}
	// The inbound-event path saves once and then throttles. The immediate
	// RotateCookies save has to land inside that window.
	handler.maybePersistRotatedCookies()

	auth.SetCookies(map[string]string{"SID": "initial", "__Secure-1PSIDTS": "rotated"})
	now = now.Add(time.Minute) // still inside the five-minute throttle
	if err := handler.PersistCookiesNow(); err != nil {
		t.Fatalf("PersistCookiesNow(): %v", err)
	}
	session, err := LoadSession(sessionPath)
	if err != nil {
		t.Fatalf("LoadSession(): %v", err)
	}
	if !strings.Contains(string(session.AuthDataJSON), "rotated") || strings.Contains(string(session.AuthDataJSON), "stale") {
		t.Fatalf("session cookies = %s", session.AuthDataJSON)
	}
}

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

func cookieNames(header string) []string {
	req := &http.Request{Header: http.Header{"Cookie": {header}}}
	var names []string
	for _, cookie := range req.Cookies() {
		names = append(names, cookie.Name)
	}
	return names
}

func copyMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
