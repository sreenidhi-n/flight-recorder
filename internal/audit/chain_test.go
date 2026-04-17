package audit

import (
	"strings"
	"testing"
)

// buildChain creates N rows with a valid hash chain.
func buildChain(n int) []ChainRow {
	rows := make([]ChainRow, n)
	prevHash := ""
	for i := range rows {
		rows[i] = ChainRow{
			ID:         strings.Repeat("a", 7) + string(rune('0'+i)),
			Ts:         "2026-01-01T00:00:00Z",
			TenantID:   1,
			ActorGHID:  42,
			ActorLogin: "alice",
			Repo:       "org/repo",
			Action:     "capability_confirmed",
			TargetID:   "cap-" + string(rune('0'+i)),
			BeforeJSON: `{}`,
			AfterJSON:  `{"decision":"confirm"}`,
			IP:         "127.0.0.1",
			UserAgent:  "test",
			PrevHash:   prevHash,
		}
		input := HashInput{
			ID:         rows[i].ID,
			Ts:         rows[i].Ts,
			TenantID:   rows[i].TenantID,
			ActorGHID:  rows[i].ActorGHID,
			ActorLogin: rows[i].ActorLogin,
			Repo:       rows[i].Repo,
			Action:     rows[i].Action,
			TargetID:   rows[i].TargetID,
			BeforeJSON: rows[i].BeforeJSON,
			AfterJSON:  rows[i].AfterJSON,
			IP:         rows[i].IP,
			UserAgent:  rows[i].UserAgent,
			PrevHash:   prevHash,
		}
		hash, _ := ComputeHash(prevHash, input)
		rows[i].Hash = hash
		prevHash = hash
	}
	return rows
}

// --- VerifyChain: happy path ---

func TestVerifyChain_ValidChain(t *testing.T) {
	rows := buildChain(5)
	result := VerifyChain(rows)
	if !result.OK {
		t.Errorf("expected OK, broken at %q", result.BrokenAtID)
	}
	if result.CheckedCount != 5 {
		t.Errorf("CheckedCount = %d, want 5", result.CheckedCount)
	}
	if result.ChainHeadHash == "" {
		t.Error("ChainHeadHash should not be empty")
	}
}

// --- VerifyChain: UPDATE breaks chain ---

func TestVerifyChain_ModifiedRow(t *testing.T) {
	rows := buildChain(5)
	// Tamper with row 2 (after the chain was computed).
	rows[2].Action = "capability_reverted" // different from what the hash covers
	result := VerifyChain(rows)
	if result.OK {
		t.Error("expected chain to be broken after modification")
	}
	if result.BrokenAtID != rows[2].ID {
		t.Errorf("BrokenAtID = %q, want %q", result.BrokenAtID, rows[2].ID)
	}
}

// --- VerifyChain: DELETE (missing row) breaks chain ---

func TestVerifyChain_DeletedRow(t *testing.T) {
	rows := buildChain(5)
	// Delete row 3: rows become [0,1,2,4] but row 4's prev_hash refers to row 3.
	rows = append(rows[:3], rows[4:]...)
	result := VerifyChain(rows)
	if result.OK {
		t.Error("expected chain to be broken after row deletion")
	}
}

// --- Empty chain ---

func TestVerifyChain_Empty(t *testing.T) {
	result := VerifyChain(nil)
	if !result.OK {
		t.Error("empty chain should report OK")
	}
}

// --- CanonicalJSON is deterministic ---

func TestCanonicalJSON_Determinism(t *testing.T) {
	v := map[string]any{
		"z": 1,
		"a": 2,
		"m": map[string]any{"b": true, "a": false},
	}
	b1, err := CanonicalJSON(v)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	b2, _ := CanonicalJSON(v)
	if string(b1) != string(b2) {
		t.Errorf("CanonicalJSON not deterministic: %q vs %q", b1, b2)
	}
	// Keys must be sorted: "a" < "m" < "z"
	s := string(b1)
	idxA := strings.Index(s, `"a"`)
	idxM := strings.Index(s, `"m"`)
	idxZ := strings.Index(s, `"z"`)
	if !(idxA < idxM && idxM < idxZ) {
		t.Errorf("keys not sorted in canonical JSON: %s", s)
	}
}

// --- RedactCode ---

func TestRedactCode_SourceCodeRedacted(t *testing.T) {
	// Long base64-like string (simulating embedded code blob).
	longB64 := strings.Repeat("A", 201)
	input := `{"content":"` + longB64 + `"}`
	out := RedactCode(input)
	if strings.Contains(out, longB64) {
		t.Error("RedactCode did not redact long base64-like string")
	}
	if !strings.Contains(out, "[redacted]") {
		t.Error("RedactCode should insert [redacted] placeholder")
	}
}

func TestRedactCode_NormalContent_Unchanged(t *testing.T) {
	normal := `{"scan_id":"abc123","decision":"confirm","decided_by":"alice"}`
	out := RedactCode(normal)
	if out != normal {
		t.Errorf("RedactCode changed normal content: %q", out)
	}
}
