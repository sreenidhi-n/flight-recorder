package auth

import (
	"context"
	"net/http"
	"net/url"
)

type contextKey string

const sessionKey contextKey = "tass_session"

// WithSession attaches a session to a context. Used by middleware that pre-validates auth.
func WithSession(ctx context.Context, sess *Session) context.Context {
	return context.WithValue(ctx, sessionKey, sess)
}

// RequireAuth returns middleware that redirects unauthenticated users to GitHub OAuth.
// The current URL is preserved in "return_to" so the user lands back in the right place.
func RequireAuth(store *SessionStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, _ := store.GetSession(r)
			if sess == nil {
				returnTo := r.URL.Path
				if r.URL.RawQuery != "" {
					returnTo += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r,
					"/auth/github?return_to="+url.QueryEscape(returnTo),
					http.StatusFound)
				return
			}
			// Attach session to context so handlers can read it without re-parsing.
			ctx := WithSession(r.Context(), sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SessionFrom retrieves the session from the request context (set by RequireAuth middleware).
// Returns nil when called outside an authenticated handler.
func SessionFrom(r *http.Request) *Session {
	sess, _ := r.Context().Value(sessionKey).(*Session)
	return sess
}

// SessionFromStore reads the session directly from the cookie (for handlers that
// opt-in to auth awareness without hard-requiring it, e.g. the root redirect).
func SessionFromStore(store *SessionStore, r *http.Request) *Session {
	sess, _ := store.GetSession(r)
	return sess
}
