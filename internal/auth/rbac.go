// Package auth — RBAC (Role-Based Access Control) for TASS.
//
// # Role Hierarchy
//
//	Viewer (1) < Developer (2) < Approver (3) < Admin (4)
//
// Derived from GitHub collaborator permission levels:
//
//	GitHub "read"     → Viewer     (can view scans, verify pages)
//	GitHub "triage"   → Developer  (can trigger manual scans)
//	GitHub "write"    → Approver   (can confirm/revert capabilities)
//	GitHub "maintain" → Admin      (everything + audit export + manifest edit)
//	GitHub "admin"    → Admin
//
// # Compliance Mapping
//
//	SOC 2 (AICPA TSP 100, 2017 TSC / 2022 PoF):
//	  CC6.1  — Logical and physical access controls
//	  CC6.3  — Role-based access, least privilege, segregation of duties
//
//	ISO/IEC 27001:2022 Annex A:
//	  A.5.15 — Access control
//	  A.5.18 — Access rights
//	  A.8.2  — Privileged access rights
//
//	NIST SP 800-53 Rev 5:
//	  AC-2   — Account Management
//	  AC-3   — Access Enforcement
//	  AC-5   — Separation of Duties
//	  AC-6   — Least Privilege
//	  AC-6(9)— Log Use of Privileged Functions
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Role represents an ordered permission level.
type Role int

const (
	RoleNone      Role = 0
	RoleViewer    Role = 1 // GitHub: read
	RoleDeveloper Role = 2 // GitHub: triage — can trigger scans
	RoleApprover  Role = 3 // GitHub: write  — can confirm/revert
	RoleAdmin     Role = 4 // GitHub: maintain or admin
)

// String returns the canonical role name for API responses and audit events.
func (r Role) String() string {
	switch r {
	case RoleViewer:
		return "viewer"
	case RoleDeveloper:
		return "developer"
	case RoleApprover:
		return "approver"
	case RoleAdmin:
		return "admin"
	default:
		return "none"
	}
}

// ParseRole converts a GitHub collaborator permission string to a Role.
func ParseRole(githubPerm string) Role {
	switch strings.ToLower(githubPerm) {
	case "admin", "maintain":
		return RoleAdmin
	case "write":
		return RoleApprover
	case "triage":
		return RoleDeveloper
	case "read":
		return RoleViewer
	default:
		return RoleNone
	}
}

// DeniedError is returned when a user's role is below the required minimum.
type DeniedError struct {
	Required Role
	Actual   Role
	Login    string
	Repo     string
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("rbac: %s requires %s on %s, got %s",
		e.Login, e.Required, e.Repo, e.Actual)
}

// PermFetcher retrieves the GitHub permission level for a user on a repo.
// Implementations call GET /repos/{owner}/{repo}/collaborators/{username}/permission.
type PermFetcher func(ctx context.Context, userAccessToken, owner, repo, login string) (string, error)

// cacheKey is used as the sync.Map key to avoid struct-as-key hashing issues.
type cacheKey struct {
	login string
	repo  string // "owner/repo"
}

type cacheEntry struct {
	role      Role
	expiresAt time.Time
}

// PermCache is a thread-safe, TTL-backed permission cache.
// One global instance per application; completely independent of the AST scanner.
// Keyed by (login, owner/repo) with a 5-minute TTL.
//
// Tenant isolation: keys always include the full "owner/repo" string, so
// user A's role on repo X never bleeds into repo Y lookups.
type PermCache struct {
	ttl time.Duration
	m   sync.Map // map[cacheKey]cacheEntry
}

// NewPermCache creates a PermCache. ttl is typically 5 minutes.
func NewPermCache(ttl time.Duration) *PermCache {
	return &PermCache{ttl: ttl}
}

func (c *PermCache) get(login, repoFull string) (Role, bool) {
	v, ok := c.m.Load(cacheKey{login, repoFull})
	if !ok {
		return RoleNone, false
	}
	e := v.(cacheEntry)
	if time.Now().After(e.expiresAt) {
		c.m.Delete(cacheKey{login, repoFull})
		return RoleNone, false
	}
	return e.role, true
}

func (c *PermCache) set(login, repoFull string, role Role) {
	c.m.Store(cacheKey{login, repoFull}, cacheEntry{
		role:      role,
		expiresAt: time.Now().Add(c.ttl),
	})
}

// Resolve returns the user's Role on the given repo, using the cache when fresh.
// On a cache miss it calls fetch, caches the result, and returns it.
func (c *PermCache) Resolve(ctx context.Context, login, accessToken, owner, repo string, fetch PermFetcher) (Role, error) {
	repoFull := owner + "/" + repo
	if cached, ok := c.get(login, repoFull); ok {
		return cached, nil
	}

	perm, err := fetch(ctx, accessToken, owner, repo, login)
	if err != nil {
		// Not a collaborator or API error — treat as no access but don't cache errors.
		return RoleNone, fmt.Errorf("rbac: resolve permission for %s on %s: %w", login, repoFull, err)
	}
	role := ParseRole(perm)
	c.set(login, repoFull, role)
	return role, nil
}

// Enforce checks that login has at least minRole on owner/repo.
// Returns (actualRole, nil) on success or (actualRole, *DeniedError) on failure.
// All permission_denied events must be audit-logged by the caller (AC-6(9)).
func (c *PermCache) Enforce(
	ctx context.Context,
	login, accessToken, owner, repo string,
	minRole Role,
	fetch PermFetcher,
) (Role, error) {
	actual, err := c.Resolve(ctx, login, accessToken, owner, repo, fetch)
	if err != nil {
		// On API error, fail closed.
		return RoleNone, &DeniedError{
			Required: minRole,
			Actual:   RoleNone,
			Login:    login,
			Repo:     owner + "/" + repo,
		}
	}
	if actual < minRole {
		return actual, &DeniedError{
			Required: minRole,
			Actual:   actual,
			Login:    login,
			Repo:     owner + "/" + repo,
		}
	}
	return actual, nil
}

// RequireRoleMiddleware returns HTTP middleware that enforces a minimum role.
// The repo is extracted from the request using repoFromReq; if it returns ("",""),
// the middleware only verifies the session is present (defers to handler).
//
// On denial it writes:
//
//	403 JSON {"error":"forbidden","required_role":"approver","actual_role":"viewer"}
func RequireRoleMiddleware(
	minRole Role,
	sessions *SessionStore,
	cache *PermCache,
	fetch PermFetcher,
	repoFromReq func(*http.Request) (owner, repo string),
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, _ := sessions.GetSession(r)
			if sess == nil {
				writeForbidden(w, "unauthenticated", minRole, RoleNone)
				return
			}

			owner, repo := repoFromReq(r)
			if owner == "" || repo == "" {
				// Repo not derivable at middleware level — proceed and let handler enforce.
				ctx := WithSession(r.Context(), sess)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			actual, err := cache.Enforce(r.Context(), sess.GitHubLogin, sess.AccessToken, owner, repo, minRole, fetch)
			if err != nil {
				writeForbidden(w, err.Error(), minRole, actual)
				return
			}

			ctx := WithSession(r.Context(), sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// EnforceInHandler is a convenience wrapper for handlers that know the repo
// at call time. Returns false and writes the 403 response if access is denied.
// The caller must return immediately when false is returned.
func EnforceInHandler(
	w http.ResponseWriter,
	r *http.Request,
	login, accessToken, owner, repo string,
	minRole Role,
	cache *PermCache,
	fetch PermFetcher,
) (Role, bool) {
	actual, err := cache.Enforce(r.Context(), login, accessToken, owner, repo, minRole, fetch)
	if err != nil {
		writeForbidden(w, err.Error(), minRole, actual)
		return actual, false
	}
	return actual, true
}

// HasMinRoleOnAnyRepo reports whether login has at least minRole on any repository
// in fullNames ("owner/repo"). Used for org-level pages (dashboard) when no single
// repo is in the URL. Returns the highest role seen across all repos (for messaging).
func HasMinRoleOnAnyRepo(ctx context.Context, login, token string, fullNames []string, minRole Role, cache *PermCache, fetch PermFetcher) (ok bool, best Role) {
	best = RoleNone
	for _, fullName := range fullNames {
		parts := strings.SplitN(fullName, "/", 2)
		if len(parts) != 2 {
			continue
		}
		role, err := cache.Resolve(ctx, login, token, parts[0], parts[1], fetch)
		if err != nil {
			continue
		}
		if role > best {
			best = role
		}
		if role >= minRole {
			return true, role
		}
	}
	return false, best
}

func writeForbidden(w http.ResponseWriter, msg string, required, actual Role) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	type resp struct {
		Error        string `json:"error"`
		RequiredRole string `json:"required_role"`
		ActualRole   string `json:"actual_role"`
	}
	_ = json.NewEncoder(w).Encode(resp{
		Error:        msg,
		RequiredRole: required.String(),
		ActualRole:   actual.String(),
	})
}

// WriteForbiddenJSON writes a 403 JSON body (for non-HTMX API-style callers).
func WriteForbiddenJSON(w http.ResponseWriter, msg string, required, actual Role) {
	writeForbidden(w, msg, required, actual)
}
