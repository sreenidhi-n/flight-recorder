// Package auth provides GitHub OAuth flow, session management,
// and authentication middleware.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

const (
	sessionCookieName = "tass_session"
	sessionMaxAge     = 7 * 24 * time.Hour
)

// Session holds the authenticated developer's data stored in the signed cookie.
type Session struct {
	GitHubLogin string    `json:"login"`
	AvatarURL   string    `json:"avatar_url"`
	AccessToken string    `json:"access_token"`
	CreatedAt   time.Time `json:"created_at"`
}

// SessionStore manages HMAC-signed cookie sessions. No external dependency.
type SessionStore struct {
	secret []byte
}

// NewSessionStore creates a SessionStore with the given HMAC secret (at least 32 bytes recommended).
func NewSessionStore(secret string) *SessionStore {
	return &SessionStore{secret: []byte(secret)}
}

// sign encodes payload as base64 and appends an HMAC-SHA256 signature.
func (s *SessionStore) sign(payload []byte) string {
	b64 := base64.URLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(b64))
	sig := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	return b64 + "." + sig
}

// verify checks the HMAC signature and returns the raw payload.
// Returns nil if the cookie is invalid or tampered.
func (s *SessionStore) verify(value string) []byte {
	idx := strings.LastIndex(value, ".")
	if idx < 0 {
		return nil
	}
	b64, sig := value[:idx], value[idx+1:]

	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(b64))
	expected := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return nil
	}

	payload, err := base64.URLEncoding.DecodeString(b64)
	if err != nil {
		return nil
	}
	return payload
}

// GetSession retrieves the verified session from the request cookie.
// Returns nil, nil when unauthenticated (no cookie or invalid signature).
func (s *SessionStore) GetSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, nil // no cookie → unauthenticated
	}
	payload := s.verify(cookie.Value)
	if payload == nil {
		return nil, nil // bad signature → unauthenticated
	}
	var sess Session
	if err := json.Unmarshal(payload, &sess); err != nil {
		return nil, nil
	}
	if time.Since(sess.CreatedAt) > sessionMaxAge {
		return nil, nil // expired
	}
	return &sess, nil
}

// SetSession writes a new session cookie to the response.
func (s *SessionStore) SetSession(w http.ResponseWriter, sess Session) error {
	payload, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	signed := s.sign(payload)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    signed,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionMaxAge.Seconds()),
	})
	return nil
}

// ClearSession removes the session cookie.
func (s *SessionStore) ClearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}
