package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OAuthConfig holds GitHub OAuth App credentials.
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	// BaseURL is the publicly reachable root (e.g. "https://app.tass.dev").
	// Used to construct the callback URL.
	BaseURL string
}

// OAuthHandler implements the GitHub OAuth 2.0 authorization code flow.
type OAuthHandler struct {
	cfg   OAuthConfig
	store *SessionStore
}

// NewOAuthHandler creates an OAuthHandler.
func NewOAuthHandler(cfg OAuthConfig, store *SessionStore) *OAuthHandler {
	return &OAuthHandler{cfg: cfg, store: store}
}

// HandleStart redirects the developer to GitHub's OAuth authorization page.
// The "return_to" query param (or referrer) is preserved in the OAuth state so
// the callback can land the user back on the exact page they were trying to reach.
func (h *OAuthHandler) HandleStart(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" || !strings.HasPrefix(returnTo, "/") {
		returnTo = "/dashboard"
	}
	params := url.Values{
		"client_id":    {h.cfg.ClientID},
		"redirect_uri": {h.callbackURL()},
		"scope":        {"read:user"},
		"state":        {returnTo},
	}
	http.Redirect(w, r,
		"https://github.com/login/oauth/authorize?"+params.Encode(),
		http.StatusFound)
}

// HandleCallback exchanges the OAuth code for a token, fetches the GitHub user,
// creates a session cookie, and redirects back to the original destination.
func (h *OAuthHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	returnTo := state
	if returnTo == "" || !strings.HasPrefix(returnTo, "/") {
		returnTo = "/dashboard"
	}

	if code == "" {
		http.Error(w, "OAuth: missing code parameter", http.StatusBadRequest)
		return
	}

	token, err := h.exchangeCode(r.Context(), code)
	if err != nil {
		slog.Error("oauth: code exchange failed", "error", err)
		http.Error(w, "Authentication failed — please try again", http.StatusInternalServerError)
		return
	}

	user, err := h.fetchUser(r.Context(), token)
	if err != nil {
		slog.Error("oauth: fetch user failed", "error", err)
		http.Error(w, "Authentication failed — please try again", http.StatusInternalServerError)
		return
	}

	sess := Session{
		GitHubLogin: user.Login,
		AvatarURL:   user.AvatarURL,
		AccessToken: token,
		CreatedAt:   time.Now().UTC(),
	}
	if err := h.store.SetSession(w, sess); err != nil {
		slog.Error("oauth: set session cookie", "error", err)
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	slog.Info("oauth: authenticated", "login", user.Login)
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// HandleLogout clears the session and redirects to the root.
func (h *OAuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.store.ClearSession(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *OAuthHandler) callbackURL() string {
	return h.cfg.BaseURL + "/auth/github/callback"
}

type githubUser struct {
	Login     string `json:"login"`
	AvatarURL string `json:"avatar_url"`
}

func (h *OAuthHandler) exchangeCode(ctx context.Context, code string) (string, error) {
	params := url.Values{
		"client_id":     {h.cfg.ClientID},
		"client_secret": {h.cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {h.callbackURL()},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://github.com/login/oauth/access_token",
		strings.NewReader(params.Encode()))
	if err != nil {
		return "", fmt.Errorf("oauth: build token request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("oauth: token exchange: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("oauth: decode token response: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("oauth: github error %s: %s", result.Error, result.ErrorDesc)
	}
	return result.AccessToken, nil
}

func (h *OAuthHandler) fetchUser(ctx context.Context, token string) (*githubUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("oauth: build user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: fetch user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauth: fetch user status %d", resp.StatusCode)
	}
	var user githubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("oauth: decode user: %w", err)
	}
	return &user, nil
}
