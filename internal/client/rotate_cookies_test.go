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
)

func TestRotateGaiaCookiesAppliesSetCookie(t *testing.T) {
	ResetGaiaCookieRotationState()
	t.Cleanup(ResetGaiaCookieRotationState)

	const rotated = "psidts-rotated"
	var (
		gotURL    string
		gotBody   string
		gotAuth   string
		gotOrigin string
		gotType   string
		gotCookie string
	)
	auth := libgm.NewAuthData()
	auth.SetCookies(map[string]string{
		"SID":              "sid-stable",
		"SAPISID":          "sap-stable",
		"__Secure-1PSIDTS": "psidts-stale",
		"__Secure-3PSIDTS": "psidts3-stale",
		"NID":              "nid-stale",
	})
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		gotURL = req.URL.String()
		body, _ := io.ReadAll(req.Body)
		gotBody = string(body)
		gotAuth = req.Header.Get("Authorization")
		gotOrigin = req.Header.Get("Origin")
		gotType = req.Header.Get("Content-Type")
		gotCookie = req.Header.Get("Cookie")
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
	if gotURL != RotateCookiesURL {
		t.Fatalf("url = %s, want %s", gotURL, RotateCookiesURL)
	}
	if gotBody != rotateCookiesBody {
		t.Fatalf("body = %q, want %q", gotBody, rotateCookiesBody)
	}
	if gotAuth != "" {
		t.Fatal("RotateCookies request included an Authorization header")
	}
	if gotOrigin != "https://accounts.google.com" || gotType != "application/json" {
		t.Fatalf("origin/type = %q / %q", gotOrigin, gotType)
	}
	if !strings.Contains(gotCookie, "SID=sid-stable") || !strings.Contains(gotCookie, "SAPISID=sap-stable") {
		t.Fatal("request did not send the stored account cookies")
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
	auth := libgm.NewAuthData()
	auth.SetCookies(map[string]string{"SID": "sid-stable", "SAPISID": "sap-stable", "__Secure-1PSIDTS": secret})
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("rejected " + secret)),
			Request:    req,
		}, nil
	})
	_, err := RotateGaiaCookies(context.Background(), auth, doer)
	if !errors.Is(err, ErrGaiaCookiesRejected) {
		t.Fatalf("error = %v, want ErrGaiaCookiesRejected", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("rejection error included a cookie value: %v", err)
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
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		header := make(http.Header)
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
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error included a cookie value: %v", err)
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
