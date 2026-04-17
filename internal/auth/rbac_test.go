package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// stubFetcher returns a fixed permission string. Use "" to simulate a non-collaborator error.
func stubFetcher(perm string) PermFetcher {
	return func(_ context.Context, _, _, _, _ string) (string, error) {
		if perm == "" {
			return "", errors.New("not a collaborator")
		}
		return perm, nil
	}
}

// --- ParseRole ---

func TestParseRole(t *testing.T) {
	tests := []struct {
		perm string
		want Role
	}{
		{"admin", RoleAdmin},
		{"maintain", RoleAdmin},
		{"write", RoleApprover},
		{"triage", RoleDeveloper},
		{"read", RoleViewer},
		{"", RoleNone},
		{"unknown", RoleNone},
		{"WRITE", RoleApprover}, // case-insensitive
	}
	for _, tc := range tests {
		got := ParseRole(tc.perm)
		if got != tc.want {
			t.Errorf("ParseRole(%q) = %v, want %v", tc.perm, got, tc.want)
		}
	}
}

// --- Role × protected-action matrix ---

// Matrix: each row is (userPerm, required, expectDenied)
func TestEnforce_RoleMatrix(t *testing.T) {
	cache := NewPermCache(5 * time.Minute)
	rows := []struct {
		userPerm  string
		required  Role
		wantDenied bool
	}{
		// Viewer can view (Viewer required)
		{"read", RoleViewer, false},
		// Viewer cannot approve
		{"read", RoleApprover, true},
		// Developer can view
		{"triage", RoleViewer, false},
		// Developer cannot approve
		{"triage", RoleApprover, true},
		// Approver can approve
		{"write", RoleApprover, false},
		// Approver cannot admin
		{"write", RoleAdmin, true},
		// Admin can do everything
		{"admin", RoleViewer, false},
		{"admin", RoleDeveloper, false},
		{"admin", RoleApprover, false},
		{"admin", RoleAdmin, false},
		// maintain is also Admin
		{"maintain", RoleAdmin, false},
		// Non-collaborator denied everything
		{"", RoleViewer, true},
	}

	for _, tc := range rows {
		// Use a distinct repo per row to avoid cache cross-contamination.
		repo := "owner/testrepo-" + tc.userPerm + "-" + tc.required.String()
		_, err := cache.Enforce(context.Background(), "alice", "tok", "owner",
			"testrepo-"+tc.userPerm+"-"+tc.required.String(),
			tc.required, stubFetcher(tc.userPerm))
		denied := err != nil
		if denied != tc.wantDenied {
			t.Errorf("perm=%q required=%v repo=%s: denied=%v want=%v",
				tc.userPerm, tc.required, repo, denied, tc.wantDenied)
		}
	}
}

// --- Cache isolation across tenants (two-repo test) ---

func TestPermCache_TenantIsolation(t *testing.T) {
	cache := NewPermCache(5 * time.Minute)

	// alice is admin on repo-a, viewer on repo-b
	fetcherA := stubFetcher("admin")
	fetcherB := stubFetcher("read")

	roleA, _ := cache.Resolve(context.Background(), "alice", "tok", "org", "repo-a", fetcherA)
	roleB, _ := cache.Resolve(context.Background(), "alice", "tok", "org", "repo-b", fetcherB)

	if roleA != RoleAdmin {
		t.Errorf("repo-a: got %v, want Admin", roleA)
	}
	if roleB != RoleViewer {
		t.Errorf("repo-b: got %v, want Viewer", roleB)
	}

	// --- Any-repo gate (org dashboard) ---

	t.Run("anyRepo_granted", func(t *testing.T) {
		c := NewPermCache(5 * time.Minute)
		fetch := func(_ context.Context, _, _, repo, _ string) (string, error) {
			switch repo {
			case "low":
				return "read", nil
			case "high":
				return "maintain", nil
			default:
				return "", errors.New("no access")
			}
		}
		ok, best := HasMinRoleOnAnyRepo(context.Background(), "alice", "tok",
			[]string{"org/low", "org/high"}, RoleAdmin, c, fetch)
		if !ok {
			t.Fatal("expected maintain on org/high to satisfy RoleAdmin")
		}
		if best != RoleAdmin {
			t.Errorf("best role: got %v", best)
		}
	})
	t.Run("anyRepo_denied", func(t *testing.T) {
		c := NewPermCache(5 * time.Minute)
		fetch := func(_ context.Context, _, _, _, _ string) (string, error) {
			return "write", nil
		}
		ok, best := HasMinRoleOnAnyRepo(context.Background(), "bob", "tok",
			[]string{"org/r1", "org/r2"}, RoleAdmin, c, fetch)
		if ok {
			t.Fatal("write on all repos should not satisfy RoleAdmin")
		}
		if best != RoleApprover {
			t.Errorf("best role: got %v, want approver", best)
		}
	})

	// Re-fetch from cache — must still be isolated.
	roleA2, _ := cache.Resolve(context.Background(), "alice", "tok", "org", "repo-a", fetcherB) // fetcher would return viewer but cache wins
	if roleA2 != RoleAdmin {
		t.Errorf("cache: repo-a role changed after re-resolve, got %v", roleA2)
	}
}

// --- TTL expiry ---

func TestPermCache_TTLExpiry(t *testing.T) {
	cache := NewPermCache(10 * time.Millisecond) // very short TTL

	cache.set("bob", "org/repo", RoleAdmin)
	if r, ok := cache.get("bob", "org/repo"); !ok || r != RoleAdmin {
		t.Fatal("expected cache hit before expiry")
	}
	time.Sleep(20 * time.Millisecond)
	if _, ok := cache.get("bob", "org/repo"); ok {
		t.Error("expected cache miss after TTL")
	}
}

// --- Stress test: 100 concurrent cache writes/reads don't corrupt ---

func TestPermCache_ConcurrentAccess(t *testing.T) {
	cache := NewPermCache(5 * time.Minute)
	fetch := stubFetcher("write")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			repo := "repo-concurrent"
			_, _ = cache.Enforce(context.Background(), "alice", "tok", "org", repo, RoleApprover, fetch)
		}(i)
	}
	wg.Wait()

	// After all concurrent accesses the role must still be Approver.
	role, err := cache.Enforce(context.Background(), "alice", "tok", "org", "repo-concurrent", RoleApprover, fetch)
	if err != nil {
		t.Fatalf("unexpected denial after stress: %v", err)
	}
	if role != RoleApprover {
		t.Errorf("role corrupted: got %v, want Approver", role)
	}
}

// --- RequireRoleMiddleware HTTP tests ---

func TestRequireRoleMiddleware_Forbidden(t *testing.T) {
	sessions := NewSessionStore("test-secret-32-bytes-long-enough!")
	cache := NewPermCache(5 * time.Minute)
	fetch := stubFetcher("read") // Viewer only

	mw := RequireRoleMiddleware(
		RoleApprover,
		sessions,
		cache,
		fetch,
		func(r *http.Request) (string, string) {
			return "org", "repo"
		},
	)

	// Build a request with a valid session for a viewer-only user.
	sess := Session{GitHubLogin: "charlie", AccessToken: "tok", CreatedAt: time.Now()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/ui/verify", nil)
	_ = sessions.SetSession(w, sess)
	// Copy the set-cookie back into the request.
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}

	w2 := httptest.NewRecorder()
	reached := false
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(w2, r)

	if reached {
		t.Error("handler should not have been reached for a viewer attempting an approver action")
	}
	if w2.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w2.Code)
	}
}

func TestRequireRoleMiddleware_Allowed(t *testing.T) {
	sessions := NewSessionStore("test-secret-32-bytes-long-enough!")
	cache := NewPermCache(5 * time.Minute)
	fetch := stubFetcher("write") // Approver

	mw := RequireRoleMiddleware(
		RoleApprover,
		sessions,
		cache,
		fetch,
		func(r *http.Request) (string, string) { return "org", "repo" },
	)

	sess := Session{GitHubLogin: "dana", AccessToken: "tok", CreatedAt: time.Now()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/ui/verify", nil)
	_ = sessions.SetSession(w, sess)
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}

	w2 := httptest.NewRecorder()
	reached := false
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(w2, r)

	if !reached {
		t.Error("handler should have been reached for an approver")
	}
}

// --- DeniedError ---

func TestDeniedError_IsDeniedError(t *testing.T) {
	cache := NewPermCache(5 * time.Minute)
	_, err := cache.Enforce(context.Background(), "eve", "tok", "org", "secret-repo",
		RoleAdmin, stubFetcher("read"))
	if err == nil {
		t.Fatal("expected denial")
	}
	var de *DeniedError
	if !errors.As(err, &de) {
		t.Errorf("expected *DeniedError, got %T: %v", err, err)
	}
	if de.Required != RoleAdmin {
		t.Errorf("Required = %v, want Admin", de.Required)
	}
	if de.Actual != RoleViewer {
		t.Errorf("Actual = %v, want Viewer", de.Actual)
	}
}
