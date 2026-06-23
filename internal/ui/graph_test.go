package ui_test

// Integration tests for the /graph endpoint suite:
//   GET /graph                         — full page + HTMX table swap
//   GET /graph?sort_by=…&sort_dir=…   — column sorting
//   GET /graph?append=1&cursor_*=…    — infinite-scroll next page
//   GET /graph?view=blast              — blast-radius SVG view
//   GET /graph/mitigation?action=show  — mitigation card partial
//   GET /graph/mitigation?action=hide  — restore button partial
//   GET /api/v1/graph                  — JSON API endpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tass-security/tass/internal/auth"
	"github.com/tass-security/tass/internal/storage"
	"github.com/tass-security/tass/internal/ui"
	"github.com/tass-security/tass/pkg/contracts"
)

// ---- seed helpers ----

const (
	testInstID int64 = 1
	testRepoA  int64 = 10
	testRepoB  int64 = 20
)

// seedGraphDB inserts a realistic set of confirmed capabilities into an
// in-memory store. Returns the store ready for use in handler tests.
//
// Layout:
//   installation 1 → testorg (AccountLogin matches the test session)
//     repo 10 → testorg/alpha   (3 capabilities: stripe, s3, postgres)
//     repo 20 → testorg/beta    (2 capabilities: redis, fastapi-http)
//
// All 5 capabilities have a "confirm" decision. Timestamps are spread
// over 5 minutes (1 min apart) so keyset pagination is deterministic.
func seedGraphDB(t *testing.T) *storage.SQLiteStore {
	t.Helper()
	s, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)

	// Installation
	if err := s.UpsertInstallation(ctx, storage.Installation{
		ID: testInstID, AccountLogin: "testorg", AccountType: "Organization",
		InstalledAt: now, AccessToken: "tok", TokenExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("upsert installation: %v", err)
	}

	// Repos
	for _, repo := range []storage.Repository{
		{ID: testRepoA, InstallationID: testInstID, FullName: "testorg/alpha", DefaultBranch: "main", CreatedAt: now},
		{ID: testRepoB, InstallationID: testInstID, FullName: "testorg/beta", DefaultBranch: "main", CreatedAt: now},
	} {
		if err := s.UpsertRepository(ctx, repo); err != nil {
			t.Fatalf("upsert repo: %v", err)
		}
	}

	type capSpec struct {
		id       string
		name     string
		category contracts.CapCategory
		evidence string
	}

	repoAcaps := []capSpec{
		{"dep:go:github.com/stripe/stripe-go", "stripe-go", contracts.CatExternalDep, "go.mod"},
		{"ast:go:aws/s3:PutObject", "S3 PutObject", contracts.CatNetworkAccess, "internal/upload.go:42"},
		{"ast:go:database/sql:DB.Exec", "SQL Write", contracts.CatDatabaseOp, "internal/repo.go:87"},
	}
	repoBcaps := []capSpec{
		{"dep:python:redis", "redis", contracts.CatExternalDep, "requirements.txt"},
		{"ast:python:fastapi:FastAPI", "FastAPI HTTP server", contracts.CatNetworkAccess, "main.py:5"},
	}

	type scanSpec struct {
		scanID string
		repoID int64
		caps   []capSpec
	}
	scans := []scanSpec{
		{"scan-alpha-1", testRepoA, repoAcaps},
		{"scan-beta-1", testRepoB, repoBcaps},
	}

	for i, ss := range scans {
		capabilities := make([]contracts.Capability, len(ss.caps))
		for j, c := range ss.caps {
			capabilities[j] = contracts.Capability{
				ID:          c.id,
				Name:        c.name,
				Category:    c.category,
				RawEvidence: c.evidence,
				Location:    contracts.CodeLocation{File: c.evidence},
			}
		}
		scanAt := now.Add(time.Duration(i) * -time.Minute)
		if err := s.SaveScan(ctx, storage.ScanResult{
			ID:           ss.scanID,
			RepoID:       ss.repoID,
			InstallationID: testInstID,
			PRNumber:     i + 1,
			CommitSHA:    fmt.Sprintf("sha%d", i),
			BaseSHA:      "base",
			ScannedAt:    scanAt,
			Capabilities: capabilities,
			NovelCount:   len(capabilities),
			Status:       storage.StatusPending,
		}); err != nil {
			t.Fatalf("save scan %s: %v", ss.scanID, err)
		}

		// Save "confirm" decisions for every capability, 1 min apart
		for k, c := range ss.caps {
			decidedAt := now.Add(time.Duration(i*10+k) * -time.Minute)
			decID := fmt.Sprintf("dec-%s-%d", ss.scanID, k)
			if err := s.SaveDecision(ctx, storage.VerificationDecision{
				ID:           decID,
				ScanID:       ss.scanID,
				CapabilityID: c.id,
				Decision:     contracts.DecisionConfirm,
				DecidedBy:    "alice",
				DecidedAt:    decidedAt,
			}); err != nil {
				t.Fatalf("save decision %s: %v", decID, err)
			}
		}
	}
	return s
}

// authedReq creates an httptest.Request with a session already injected into
// its context, bypassing the OAuth / cookie flow entirely.
func authedReq(method, target string) *http.Request {
	sess := &auth.Session{
		GitHubLogin: "testorg",
		AvatarURL:   "https://example.com/av.png",
		AccessToken: "test-token",
		CreatedAt:   time.Now().UTC(),
	}
	ctx := auth.WithSession(context.Background(), sess)
	return httptest.NewRequest(method, target, nil).WithContext(ctx)
}

// ---- GraphPageHandler tests ----

func TestGraphPage_FullLoad(t *testing.T) {
	s := seedGraphDB(t)
	h := ui.NewGraphPageHandler(s, nil, nil, nil)

	req := authedReq("GET", "/graph")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Capability Graph") {
		t.Error("expected page title 'Capability Graph'")
	}
	if !strings.Contains(body, "stripe-go") {
		t.Error("expected capability 'stripe-go' in full page")
	}
	if !strings.Contains(body, "testorg/alpha") {
		t.Error("expected repo 'testorg/alpha' in table")
	}
	if !strings.Contains(body, "testorg/beta") {
		t.Error("expected repo 'testorg/beta' in table")
	}
}

func TestGraphPage_HTMXFilterSwap(t *testing.T) {
	s := seedGraphDB(t)
	h := ui.NewGraphPageHandler(s, nil, nil, nil)

	req := authedReq("GET", "/graph")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	// HTMX swap returns GraphTable which wraps in <div id="graph-section">
	if !strings.Contains(body, `id="graph-section"`) {
		t.Error("HTMX response must contain <div id='graph-section'>")
	}
	// Full page chrome (nav, footer) must NOT be present
	if strings.Contains(body, `<html`) {
		t.Error("HTMX response must not contain full HTML shell")
	}
}

func TestGraphPage_CategoryFilter(t *testing.T) {
	s := seedGraphDB(t)
	h := ui.NewGraphPageHandler(s, nil, nil, nil)

	req := authedReq("GET", "/graph?category=network_access")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	// Only network_access caps should appear
	if !strings.Contains(body, "S3 PutObject") {
		t.Error("expected S3 PutObject (network_access) in filtered results")
	}
	if !strings.Contains(body, "FastAPI HTTP server") {
		t.Error("expected FastAPI HTTP server (network_access) in filtered results")
	}
	// external_dependency caps must be absent
	if strings.Contains(body, "stripe-go") {
		t.Error("stripe-go (external_dependency) must not appear when filter=network_access")
	}
}

func TestGraphPage_SearchFilter(t *testing.T) {
	s := seedGraphDB(t)
	h := ui.NewGraphPageHandler(s, nil, nil, nil)

	req := authedReq("GET", "/graph?q=stripe")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "stripe-go") {
		t.Error("expected stripe-go to match search 'stripe'")
	}
	if strings.Contains(body, "redis") {
		t.Error("redis must not appear when searching 'stripe'")
	}
}

func TestGraphPage_RepoFilter(t *testing.T) {
	s := seedGraphDB(t)
	h := ui.NewGraphPageHandler(s, nil, nil, nil)

	req := authedReq("GET", "/graph?repo=testorg%2Fbeta")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "redis") {
		t.Error("expected beta-repo cap 'redis'")
	}
	if strings.Contains(body, "stripe-go") {
		t.Error("alpha-repo caps must not appear when filtering by beta repo")
	}
}

func TestGraphPage_EmptyResults(t *testing.T) {
	s := seedGraphDB(t)
	h := ui.NewGraphPageHandler(s, nil, nil, nil)

	req := authedReq("GET", "/graph?q=zzz_does_not_exist")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "No confirmed capabilities") {
		t.Error("expected empty-state message")
	}
}

// ---- Task 2: Column sorting ----

func TestGraphPage_SortByRepo(t *testing.T) {
	s := seedGraphDB(t)
	h := ui.NewGraphPageHandler(s, nil, nil, nil)

	req := authedReq("GET", "/graph?sort_by=repo&sort_dir=asc")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	// Both repos must appear; alpha sorts before beta
	alphaPos := strings.Index(body, "testorg/alpha")
	betaPos := strings.Index(body, "testorg/beta")
	if alphaPos == -1 || betaPos == -1 {
		t.Fatal("both repos must appear in sorted output")
	}
	if alphaPos > betaPos {
		t.Error("sort_by=repo sort_dir=asc: alpha should appear before beta")
	}
}

func TestGraphPage_SortByCategory(t *testing.T) {
	s := seedGraphDB(t)
	h := ui.NewGraphPageHandler(s, nil, nil, nil)

	req := authedReq("GET", "/graph?sort_by=category&sort_dir=asc")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("sort by category: status %d", rec.Code)
	}
	body := rec.Body.String()
	// database_operation < external_dependency < network_access (lexicographic)
	dbPos := strings.Index(body, "SQL Write")
	depPos := strings.Index(body, "stripe-go")
	netPos := strings.Index(body, "S3 PutObject")
	if dbPos == -1 || depPos == -1 || netPos == -1 {
		t.Fatal("all capabilities must appear in category-sorted output")
	}
	if !(dbPos < depPos && depPos < netPos) {
		t.Errorf("category ASC order wrong: db=%d dep=%d net=%d", dbPos, depPos, netPos)
	}
}

func TestGraphPage_SortByCapabilityDesc(t *testing.T) {
	s := seedGraphDB(t)
	h := ui.NewGraphPageHandler(s, nil, nil, nil)

	req := authedReq("GET", "/graph?sort_by=capability&sort_dir=desc")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}
	body := rec.Body.String()
	// DESC: "stripe-go" > "redis" > "SQL Write" > "S3 PutObject" > "FastAPI…"
	stripePos := strings.Index(body, "stripe-go")
	fastPos := strings.Index(body, "FastAPI")
	if stripePos == -1 || fastPos == -1 {
		t.Fatal("expected stripe-go and FastAPI in output")
	}
	if stripePos > fastPos {
		t.Error("capability DESC: stripe-go should appear before FastAPI")
	}
}

// ---- Task 1: Keyset pagination / infinite scroll ----

func TestGraphPage_InfiniteScroll_Append(t *testing.T) {
	s := seedGraphDB(t)
	h := ui.NewGraphPageHandler(s, nil, nil, nil)

	// Fetch all 5 caps first to get a valid cursor for the second page
	// Use PageSize=2 by manipulating the handler constant — since we can't change
	// it externally, we rely on the handler returning the sentinel when HasMore.
	// With 5 rows and pageSize=50 there's no next page. To test the append path
	// we hit the endpoint directly with append=1 and no cursor (returns first page).
	req := authedReq("GET", "/graph?append=1")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	// append=1 returns GraphRowsBatch — just <tr> elements, no wrapping div
	if strings.Contains(body, `id="graph-section"`) {
		t.Error("append response must not contain graph-section wrapper")
	}
	if strings.Contains(body, "<html") {
		t.Error("append response must not contain HTML shell")
	}
	// Must contain capability data
	if !strings.Contains(body, "stripe-go") && !strings.Contains(body, "redis") {
		t.Error("append response must contain at least one capability row")
	}
}

func TestGraphPage_InfiniteScroll_Cursor(t *testing.T) {
	s := seedGraphDB(t)
	h := ui.NewGraphPageHandler(s, nil, nil, nil)

	// Pick a cursor timestamp between the 3rd and 4th capability's decided_at.
	// The decisions were seeded at: now, now-1m, now-2m, now-10m, now-11m
	// A cursor at now-3m should return caps 4 and 5 (now-10m and now-11m).
	cursorTime := time.Now().UTC().Add(-3 * time.Minute).Format(time.RFC3339)
	cursorID := "zzz-sentinel" // larger than real IDs at same time

	target := fmt.Sprintf("/graph?append=1&cursor_time=%s&cursor_id=%s",
		strings.ReplaceAll(cursorTime, ":", "%3A"), cursorID)
	req := authedReq("GET", target)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}
	body := rec.Body.String()
	// Caps decided before now-3m: redis (now-10m) and fastapi (now-11m)
	if !strings.Contains(body, "redis") {
		t.Error("cursor page should contain redis (decided at now-10m)")
	}
	if !strings.Contains(body, "FastAPI") {
		t.Error("cursor page should contain FastAPI (decided at now-11m)")
	}
	// Caps decided after now-3m should NOT appear in this page
	if strings.Contains(body, "stripe-go") {
		t.Error("stripe-go is on page 1 and must not appear on cursor page")
	}
}

// ---- Task 3: Mitigation partials ----

func TestGraphMitigation_ShowCard(t *testing.T) {
	h := ui.NewGraphMitigationHandler(nil)

	req := authedReq("GET",
		"/graph/mitigation?action=show"+
			"&row_id=mit-test&cap_id=ast-go-net-http&cap_name=HTTP+Client"+
			"&category=network_access&location_file=main.go&evidence=http.Get()")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	// Card must contain the mitigation heading for network_access
	if !strings.Contains(body, "NetworkPolicy") {
		t.Error("network_access mitigation should contain 'NetworkPolicy'")
	}
	// Card must contain the Hide button pointing back to the same row_id
	if !strings.Contains(body, "mit-test") {
		t.Error("hide button must reference the same row_id")
	}
	if !strings.Contains(body, "action=hide") {
		t.Error("card must contain a hide action link")
	}
}

func TestGraphMitigation_ShowCard_Database(t *testing.T) {
	h := ui.NewGraphMitigationHandler(nil)

	req := authedReq("GET",
		"/graph/mitigation?action=show"+
			"&row_id=mit-db&cap_id=ast-go-db-exec&cap_name=DB+Write"+
			"&category=database_operation")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "GRANT") && !strings.Contains(body, "sql") {
		t.Error("database_operation mitigation should contain SQL GRANT snippet")
	}
}

func TestGraphMitigation_ShowCard_Privilege(t *testing.T) {
	h := ui.NewGraphMitigationHandler(nil)

	req := authedReq("GET",
		"/graph/mitigation?action=show"+
			"&row_id=mit-priv&cap_id=ast-go-priv&cap_name=Privilege+Op"+
			"&category=privilege_pattern")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "drop") && !strings.Contains(body, "capabilities") {
		t.Error("privilege_pattern mitigation should reference 'drop capabilities'")
	}
}

func TestGraphMitigation_ShowCard_GenericCategory(t *testing.T) {
	h := ui.NewGraphMitigationHandler(nil)

	req := authedReq("GET",
		"/graph/mitigation?action=show"+
			"&row_id=mit-unk&cap_id=some-id&cap_name=Unknown"+
			"&category=external_dependency")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	// external_dependency has no specific IaC — should show generic advisory
	if !strings.Contains(body, "No IaC template") && !strings.Contains(body, "tass.contract.yaml") {
		t.Error("external_dependency should render generic advisory, not a code snippet")
	}
}

func TestGraphMitigation_HideRestoresButton(t *testing.T) {
	h := ui.NewGraphMitigationHandler(nil)

	req := authedReq("GET",
		"/graph/mitigation?action=hide"+
			"&row_id=mit-test&cap_id=ast-go-net-http&cap_name=HTTP+Client"+
			"&category=network_access")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	// Hide response must return the original Mitigate button (not a card)
	if !strings.Contains(body, "Mitigate") {
		t.Error("hide response should restore the ⚡ Mitigate button")
	}
	if strings.Contains(body, "NetworkPolicy") {
		t.Error("hide response must NOT contain the mitigation snippet")
	}
	// The restored button must target the same row_id
	if !strings.Contains(body, "mit-test") {
		t.Error("restored button must reference the same row_id")
	}
}

func TestGraphMitigation_RequiresAuth(t *testing.T) {
	h := ui.NewGraphMitigationHandler(nil)
	// No session in context
	req := httptest.NewRequest("GET", "/graph/mitigation?action=show", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated request should get 401, got %d", rec.Code)
	}
}

// ---- Task 5: Blast radius view ----

func TestGraphPage_BlastRadiusView(t *testing.T) {
	s := seedGraphDB(t)
	h := ui.NewGraphPageHandler(s, nil, nil, nil)

	req := authedReq("GET", "/graph?view=blast")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}
	body := rec.Body.String()
	// Must contain an inline SVG
	if !strings.Contains(body, "<svg") {
		t.Error("blast radius view must contain an inline SVG element")
	}
	if !strings.Contains(body, "</svg>") {
		t.Error("blast radius SVG must be closed")
	}
	// SVG must have <circle> nodes and <line> edges
	if !strings.Contains(body, "<circle") {
		t.Error("SVG must contain circle nodes")
	}
	if !strings.Contains(body, "<line") {
		t.Error("SVG must contain line edges")
	}
	// Repo labels must appear
	if !strings.Contains(body, "testorg/alpha") {
		t.Error("blast radius SVG must label the testorg/alpha repo node")
	}
	if !strings.Contains(body, "testorg/beta") {
		t.Error("blast radius SVG must label the testorg/beta repo node")
	}
	// Must NOT include the table header
	if strings.Contains(body, "<thead>") {
		t.Error("blast radius view must not render the capabilities table")
	}
}

func TestGraphPage_BlastRadiusEmpty(t *testing.T) {
	// Empty store: no capabilities — SVG should show empty-state message
	s, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	_ = s.UpsertInstallation(ctx, storage.Installation{
		ID: testInstID, AccountLogin: "testorg", AccountType: "Organization",
		InstalledAt: time.Now().UTC(),
	})

	h := ui.NewGraphPageHandler(s, nil, nil, nil)
	req := authedReq("GET", "/graph?view=blast")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "No confirmed capabilities") {
		t.Error("empty blast radius view should show empty-state message")
	}
}

// ---- Task 4: JSON API ----

func TestApiGraph_JSON(t *testing.T) {
	s := seedGraphDB(t)
	h := ui.NewApiGraphHandler(s, nil, nil, nil)

	req := authedReq("GET", "/api/v1/graph")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}

	var resp struct {
		Capabilities []struct {
			RepoFullName string    `json:"RepoFullName"`
			Name         string    `json:"Name"`
			Category     string    `json:"Category"`
			ConfirmedBy  string    `json:"ConfirmedBy"`
			ConfirmedAt  time.Time `json:"ConfirmedAt"`
		} `json:"capabilities"`
		HasMore        bool   `json:"has_more"`
		NextCursorTime string `json:"next_cursor_time,omitempty"`
		Total          int    `json:"total"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if resp.Total != 5 {
		t.Errorf("total: got %d, want 5", resp.Total)
	}
	if resp.HasMore {
		t.Error("has_more should be false for 5 caps with pageSize=50")
	}
	// Verify all 5 caps are present
	names := make(map[string]bool)
	for _, c := range resp.Capabilities {
		names[c.Name] = true
	}
	for _, want := range []string{"stripe-go", "S3 PutObject", "SQL Write", "redis", "FastAPI HTTP server"} {
		if !names[want] {
			t.Errorf("missing capability %q in JSON response", want)
		}
	}
}

func TestApiGraph_CategoryFilter_JSON(t *testing.T) {
	s := seedGraphDB(t)
	h := ui.NewApiGraphHandler(s, nil, nil, nil)

	req := authedReq("GET", "/api/v1/graph?category=database_operation")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}
	var resp struct {
		Capabilities []struct{ Name string } `json:"capabilities"`
		Total        int                     `json:"total"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Total != 1 {
		t.Errorf("database_operation filter: got %d caps, want 1", resp.Total)
	}
	if len(resp.Capabilities) > 0 && resp.Capabilities[0].Name != "SQL Write" {
		t.Errorf("expected 'SQL Write', got %q", resp.Capabilities[0].Name)
	}
}

func TestApiGraph_Pagination_JSON(t *testing.T) {
	s := seedGraphDB(t)
	h := ui.NewApiGraphHandler(s, nil, nil, nil)

	// All 5 caps fit in the default page size of 50 → no cursor expected
	req := authedReq("GET", "/api/v1/graph")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var resp struct {
		HasMore        bool   `json:"has_more"`
		NextCursorTime string `json:"next_cursor_time,omitempty"`
		NextCursorID   string `json:"next_cursor_id,omitempty"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&resp)

	if resp.HasMore {
		t.Error("5 caps with pageSize=50 should not need pagination")
	}
	if resp.NextCursorTime != "" {
		t.Error("next_cursor_time should be empty when all results fit in one page")
	}
}

func TestApiGraph_RequiresAuth(t *testing.T) {
	s := seedGraphDB(t)
	h := ui.NewApiGraphHandler(s, nil, nil, nil)

	req := httptest.NewRequest("GET", "/api/v1/graph", nil) // no session
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated request: got %d, want 401", rec.Code)
	}
}

// ---- CSV export ----

func TestGraphPage_CSVExport(t *testing.T) {
	s := seedGraphDB(t)
	h := ui.NewGraphPageHandler(s, nil, nil, nil)

	req := authedReq("GET", "/graph?format=csv")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type: got %q, want text/csv", ct)
	}
	body := rec.Body.String()
	// CSV header row
	if !strings.Contains(body, "repo,capability,category,endpoint,confirmed_by,confirmed_at") {
		t.Error("CSV missing header row")
	}
	// Data rows
	if !strings.Contains(body, "stripe-go") {
		t.Error("CSV missing stripe-go")
	}
	if !strings.Contains(body, "redis") {
		t.Error("CSV missing redis")
	}
}

// ---- Unauthenticated redirect ----

func TestGraphPage_UnauthenticatedRedirects(t *testing.T) {
	s := seedGraphDB(t)
	h := ui.NewGraphPageHandler(s, nil, nil, nil)

	req := httptest.NewRequest("GET", "/graph", nil) // no session
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("unauthenticated: got %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "/auth/github") {
		t.Errorf("redirect location: got %q, want /auth/github path", loc)
	}
}
