// Package audit implements the tamper-evident hash chain for TASS audit events.
//
// # Hash chain design (NIST AU-9(3) + AU-10(3))
//
// Each audit event stores:
//
//	prev_hash = hash of the previous event for the same tenant (empty for the first)
//	hash      = sha256(prev_hash || canonical_json(event_without_hash))
//
// "canonical JSON" means: keys sorted, no insignificant whitespace, UTF-8.
// The chain is per-tenant (scoped by tenant_id / installation_id) so that
// one customer's events cannot affect another customer's chain integrity —
// critical for multi-tenant NIST AU-9 compliance.
//
// Verification: GET /audit/:repo/verify re-derives every hash in order and
// reports the first row where the stored hash diverges from the computed one.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// HashInput is the portion of an AuditEvent that is included in the hash.
// The `hash` field itself is excluded (obviously); all other fields are included.
type HashInput struct {
	ID         string `json:"id"`
	Ts         string `json:"ts"`
	TenantID   int64  `json:"tenant_id"`
	ActorGHID  int64  `json:"actor_gh_id"`
	ActorLogin string `json:"actor_login"`
	Repo       string `json:"repo"`
	Action     string `json:"action"`
	TargetID   string `json:"target_id"`
	BeforeJSON string `json:"before_json"`
	AfterJSON  string `json:"after_json"`
	IP         string `json:"ip"`
	UserAgent  string `json:"user_agent"`
	PrevHash   string `json:"prev_hash"`
}

// CanonicalJSON returns a deterministic JSON encoding of v:
// keys sorted, no extra whitespace, UTF-8.
// This is the canonical form used in the hash chain (AU-10 non-repudiation).
func CanonicalJSON(v any) ([]byte, error) {
	// Marshal normally first.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical_json: marshal: %w", err)
	}

	// Unmarshal into a generic map and re-sort keys via a recursive helper.
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, fmt.Errorf("canonical_json: unmarshal: %w", err)
	}

	sorted := sortKeys(generic)
	out, err := json.Marshal(sorted)
	if err != nil {
		return nil, fmt.Errorf("canonical_json: re-marshal: %w", err)
	}
	return out, nil
}

// sortKeys recursively sorts map keys. Other types are returned as-is.
func sortKeys(v any) any {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		// Use a JSON-encoded ordered representation via json.RawMessage.
		// We build a string manually so key order is preserved.
		var sb strings.Builder
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			sb.Write(kb)
			sb.WriteByte(':')
			vb, _ := json.Marshal(sortKeys(val[k]))
			sb.Write(vb)
		}
		sb.WriteByte('}')
		var out any
		_ = json.Unmarshal([]byte(sb.String()), &out)
		return out
	case []any:
		for i, item := range val {
			val[i] = sortKeys(item)
		}
		return val
	default:
		return v
	}
}

// ComputeHash derives the hash for one audit event.
//
//	hash = sha256(prev_hash || canonical_json(input))
func ComputeHash(prevHash string, input HashInput) (string, error) {
	canonical, err := CanonicalJSON(input)
	if err != nil {
		return "", fmt.Errorf("compute_hash: %w", err)
	}

	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyResult is the outcome of a chain verification run.
type VerifyResult struct {
	OK           bool   // true when every hash is consistent
	BrokenAtID   string // first event ID where the chain breaks (empty when OK)
	CheckedCount int    // number of events verified
	ChainHeadHash string // hash of the last (most recent) event in the chain
}

// ChainRow is a minimal record for chain verification — fetched cheaply from DB.
type ChainRow struct {
	ID         string
	Ts         string
	TenantID   int64
	ActorGHID  int64
	ActorLogin string
	Repo       string
	Action     string
	TargetID   string
	BeforeJSON string
	AfterJSON  string
	IP         string
	UserAgent  string
	PrevHash   string
	Hash       string // stored value to verify against
}

// VerifyChain checks the integrity of the hash chain for a set of rows
// ordered by ts ASC for the same tenant.
// Rows must be in ascending timestamp order; the first row must have PrevHash=="".
func VerifyChain(rows []ChainRow) VerifyResult {
	if len(rows) == 0 {
		return VerifyResult{OK: true}
	}

	prevHash := ""
	for _, row := range rows {
		input := HashInput{
			ID:         row.ID,
			Ts:         row.Ts,
			TenantID:   row.TenantID,
			ActorGHID:  row.ActorGHID,
			ActorLogin: row.ActorLogin,
			Repo:       row.Repo,
			Action:     row.Action,
			TargetID:   row.TargetID,
			BeforeJSON: row.BeforeJSON,
			AfterJSON:  row.AfterJSON,
			IP:         row.IP,
			UserAgent:  row.UserAgent,
			PrevHash:   prevHash,
		}
		computed, err := ComputeHash(prevHash, input)
		if err != nil {
			return VerifyResult{BrokenAtID: row.ID}
		}
		if computed != row.Hash {
			return VerifyResult{
				OK:           false,
				BrokenAtID:   row.ID,
				CheckedCount: 0, // will be set by caller
			}
		}
		prevHash = row.Hash
	}
	return VerifyResult{
		OK:            true,
		ChainHeadHash: prevHash,
		CheckedCount:  len(rows),
	}
}
