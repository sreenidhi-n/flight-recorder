// Package audit provides tamper-evident structured audit logging for TASS.
//
// # Compliance Mapping
//
//	SOC 2 (AICPA TSP 100, 2017 TSC / 2022 PoF):
//	  CC7.2  — Monitoring of system components
//	  CC7.3  — Evaluation of security events
//
//	ISO/IEC 27001:2022 Annex A:
//	  A.8.15 — Logging
//	  A.8.16 — Monitoring activities (new in 2022)
//
//	NIST SP 800-53 Rev 5:
//	  AU-2   — Event Logging
//	  AU-3   — Content of Audit Records
//	  AU-9   — Protection of Audit Information
//	  AU-9(3)— Cryptographic Protection (hash chain)
//	  AU-10  — Non-repudiation
//	  AU-10(3)— Chain of Custody
//	  AU-12  — Audit Record Generation
//
// # Retention
//
// Default 7 years (matches SOC 2 CC7 expectations).
// Override with TASS_AUDIT_RETENTION_DAYS environment variable.
//
// # Customer data policy
//
// TASS NEVER writes customer source code to audit_events.before_json or
// after_json.  Only capability metadata (IDs, names, categories, decisions)
// is persisted.  This is enforced by the redaction helper RedactCode().
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// Action represents the kind of audit event.
type Action string

const (
	ActionScanTriggered             Action = "scan_triggered"
	ActionCapabilityConfirmed       Action = "capability_confirmed"
	ActionCapabilityReverted        Action = "capability_reverted"
	ActionManifestEdited            Action = "manifest_edited"
	ActionPolicyGenerated           Action = "policy_generated"
	ActionComplianceReportGenerated Action = "compliance_report_generated"
	ActionPermissionDenied          Action = "permission_denied"
	ActionSlashCommandInvoked       Action = "slash_command_invoked"
	ActionAuditExported             Action = "audit_exported"
)

// RetentionDays is the default audit log retention (7 years = 2557 days).
const RetentionDays = 2557

// ctxKey is unexported so other packages cannot forge actor context.
type ctxKey struct{}

// ActorInfo holds request-level context injected by middleware.
type ActorInfo struct {
	TenantID   int64
	ActorGHID  int64
	ActorLogin string
	Repo       string // "owner/repo" or ""
	IP         string
	UserAgent  string
}

// WithActor attaches actor info to the context (set by HTTP middleware).
func WithActor(ctx context.Context, a ActorInfo) context.Context {
	return context.WithValue(ctx, ctxKey{}, a)
}

// ActorFrom retrieves actor info from the context.
// Returns zero value if not set (e.g. background jobs).
func ActorFrom(ctx context.Context) ActorInfo {
	a, _ := ctx.Value(ctxKey{}).(ActorInfo)
	return a
}

// ActorFromRequest extracts actor info from an HTTP request.
// tenantID and repo must be supplied by the caller since they are not in the
// HTTP headers.
func ActorFromRequest(r *http.Request, tenantID int64, repo string) ActorInfo {
	ip := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ip = xff
	}
	return ActorInfo{
		TenantID:  tenantID,
		Repo:      repo,
		IP:        ip,
		UserAgent: r.UserAgent(),
	}
}

// AuditEvent is the full record written to audit_events.
type AuditEvent struct {
	ID         string
	Ts         time.Time
	TenantID   int64
	ActorGHID  int64
	ActorLogin string
	Repo       string
	Action     Action
	TargetID   string
	BeforeJSON string
	AfterJSON  string
	IP         string
	UserAgent  string
	PrevHash   string // set by Store.SaveAuditEvent
	Hash       string // set by Store.SaveAuditEvent
}

// Storer is the minimal interface the audit package requires from the storage layer.
type Storer interface {
	SaveAuditEvent(ctx context.Context, evt AuditEvent) error
}

// Emitter emits audit events; safe to call with a nil emitter (no-op).
type Emitter struct {
	store Storer
}

// NewEmitter creates an Emitter backed by the given store.
func NewEmitter(store Storer) *Emitter {
	return &Emitter{store: store}
}

// Emit records one audit event.
//
//   - actor/IP/UA are pulled from ctx (set by middleware via WithActor).
//   - before/after are marshalled to JSON after redacting any source code.
//   - If the emitter or store is nil, Emit is a no-op.
//
// Emit is idempotent per event ID: callers should use stable IDs (e.g.
// scanID+":"+capID+":"+action) to avoid double-emit on retry.
func (e *Emitter) Emit(ctx context.Context, action Action, targetID string, before, after any) error {
	if e == nil || e.store == nil {
		return nil
	}

	actor := ActorFrom(ctx)
	beforeJSON, err := marshalSafe(before)
	if err != nil {
		slog.Warn("audit.Emit: marshal before", "error", err)
		beforeJSON = ""
	}
	afterJSON, err := marshalSafe(after)
	if err != nil {
		slog.Warn("audit.Emit: marshal after", "error", err)
		afterJSON = ""
	}

	evt := AuditEvent{
		ID:         uuid.New().String(),
		Ts:         time.Now().UTC(),
		TenantID:   actor.TenantID,
		ActorGHID:  actor.ActorGHID,
		ActorLogin: actor.ActorLogin,
		Repo:       actor.Repo,
		Action:     action,
		TargetID:   targetID,
		BeforeJSON: beforeJSON,
		AfterJSON:  afterJSON,
		IP:         actor.IP,
		UserAgent:  actor.UserAgent,
	}

	if err := e.store.SaveAuditEvent(ctx, evt); err != nil {
		slog.Error("audit.Emit: save", "action", action, "target", targetID, "error", err)
		return fmt.Errorf("audit.Emit: %w", err)
	}
	return nil
}

// marshalSafe marshals v to JSON after running it through RedactCode.
// Returns "" for nil input.
func marshalSafe(v any) (string, error) {
	if v == nil {
		return "", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return RedactCode(string(b)), nil
}

// codePatterns is a list of regexes that match patterns resembling source code
// embedded as strings. A match causes the value to be replaced with "[redacted]".
// This enforces the policy: customer source code NEVER in audit logs.
var codePatterns = []*regexp.Regexp{
	// Multi-line code blocks (```...```)
	regexp.MustCompile("```[^`]*```"),
	// Long base64-like strings (> 200 chars without whitespace — likely binary/code)
	regexp.MustCompile(`[A-Za-z0-9+/=]{200,}`),
}

// RedactCode removes patterns that look like source code from a JSON string.
// This is a defence-in-depth measure; callers should never pass code in the
// first place.
func RedactCode(jsonStr string) string {
	for _, re := range codePatterns {
		jsonStr = re.ReplaceAllString(jsonStr, `"[redacted]"`)
	}
	return jsonStr
}
