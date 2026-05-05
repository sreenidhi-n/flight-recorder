package compliance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/tass-security/tass/internal/audit"
	"github.com/tass-security/tass/internal/storage"
	"github.com/tass-security/tass/pkg/contracts"
)

// ErrChainBroken is returned when the audit hash chain fails verification.
// Callers must not silently suppress this — the report is not trustworthy evidence.
var ErrChainBroken = errors.New("audit chain integrity broken")

// capState tracks the latest-known state of one capability across all scans.
type capState struct {
	cap      contracts.Capability
	decision string    // "confirmed" | "reverted" | "unconfirmed"
	by       string    // actor login
	at       time.Time // decision time
	scanTime time.Time // scan that provided this snapshot (latest wins)
}

// --- Report types (all slice fields, no maps — guarantees deterministic JSON marshaling) ---

// Summary is the executive summary section of the report.
type Summary struct {
	TotalScans        int    `json:"total_scans"`
	TotalCapabilities int    `json:"total_capabilities"`
	ConfirmedCount    int    `json:"confirmed_count"`
	RevertedCount     int    `json:"reverted_count"`
	UnconfirmedCount  int    `json:"unconfirmed_count"`
	AuditChainIntact  bool   `json:"audit_chain_intact"`
	ChainCheckedCount int    `json:"chain_checked_count"`
	ChainHeadHash     string `json:"chain_head_hash,omitempty"`
}

// ControlRef is one control ID with its framework label.
type ControlRef struct {
	Framework string `json:"framework"`
	ControlID string `json:"control_id"`
}

// CapabilityReport is one row in the capabilities table.
type CapabilityReport struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Category    string       `json:"category"`
	Source      string       `json:"source"`
	ConfirmedBy string       `json:"confirmed_by,omitempty"`
	ConfirmedAt string       `json:"confirmed_at,omitempty"`
	Decision    string       `json:"decision"` // "confirmed" | "reverted" | "unconfirmed"
	ControlRefs []ControlRef `json:"control_refs"` // sorted by framework+id
}

// ControlMatrixEntry maps one control ID to the capabilities that evidence it.
type ControlMatrixEntry struct {
	Framework     string   `json:"framework"`
	ControlID     string   `json:"control_id"`
	CapabilityIDs []string `json:"capability_ids"` // sorted
	HasEvidence   bool     `json:"has_evidence"`   // true if ≥1 confirmed capability
}

// TassControlReport is one row in the TASS self-attestation section.
type TassControlReport struct {
	Name          string       `json:"name"`
	ImplementedBy string       `json:"implemented_by"`
	ControlRefs   []ControlRef `json:"control_refs"`
}

// ChainAttestation is the result of verifying the audit hash chain.
type ChainAttestation struct {
	OK            bool   `json:"ok"`
	BrokenAtID    string `json:"broken_at_id,omitempty"`
	CheckedCount  int    `json:"checked_count"`
	ChainHeadHash string `json:"chain_head_hash,omitempty"`
}

// FrameworkVersion lists the exact document version used for a framework.
type FrameworkVersion struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	Authority string `json:"authority"`
}

// ReportData is the canonical payload — all slice fields, no maps.
// JSON-marshaling this struct is deterministic for the same input, enabling
// a stable report_hash.
type ReportData struct {
	Repo              string               `json:"repo"`
	Framework         string               `json:"framework"`
	Since             string               `json:"since,omitempty"`
	Summary           Summary              `json:"executive_summary"`
	Capabilities      []CapabilityReport   `json:"capabilities"`
	ControlMatrix     []ControlMatrixEntry `json:"control_matrix"`
	Unconfirmed       []CapabilityReport   `json:"unconfirmed_capabilities"`
	TassControls      []TassControlReport  `json:"tass_product_controls"`
	ChainAttestation  ChainAttestation     `json:"audit_chain_attestation"`
	FrameworkVersions []FrameworkVersion   `json:"framework_versions"`
}

// Report is the final output including non-deterministic metadata.
type Report struct {
	ReportHash   string     `json:"report_hash"`
	GenerationTs time.Time  `json:"generation_ts"`
	TassVersion  string     `json:"tass_version"`
	Data         ReportData `json:"data"`
}

// Generator produces compliance reports from TASS scan data.
type Generator struct {
	store   storage.Store
	version string
}

// NewGenerator creates a Generator backed by the given store.
func NewGenerator(store storage.Store, version string) *Generator {
	return &Generator{store: store, version: version}
}

// Generate builds the full compliance report for the given repo.
//
// framework must be one of: "soc2", "iso27001", "nist80053", "all".
// since, if non-nil, restricts scans to those taken after the given time.
//
// Returns ErrChainBroken (use errors.Is) when chain verification fails.
// Callers MUST propagate or prominently display this — do not silently continue.
func (g *Generator) Generate(ctx context.Context, repoFullName, framework string, since *time.Time) (*Report, error) {
	repo, err := g.store.FindRepoByName(ctx, repoFullName)
	if err != nil {
		return nil, fmt.Errorf("compliance: look up repo %q: %w", repoFullName, err)
	}
	if repo == nil {
		return nil, fmt.Errorf("compliance: repo %q not found in database", repoFullName)
	}

	// Fetch all scans (high limit — compliance generation is a rare operation).
	scans, err := g.store.GetScansByRepo(ctx, repo.ID, 10_000)
	if err != nil {
		return nil, fmt.Errorf("compliance: get scans: %w", err)
	}
	if since != nil {
		filtered := scans[:0]
		for _, s := range scans {
			if s.ScannedAt.After(*since) {
				filtered = append(filtered, s)
			}
		}
		scans = filtered
	}

	// Collect decisions per scan.
	decisionsByScan := make(map[string][]storage.VerificationDecision, len(scans))
	for _, s := range scans {
		ds, err := g.store.GetDecisionsByScan(ctx, s.ID)
		if err != nil {
			return nil, fmt.Errorf("compliance: get decisions for scan %s: %w", s.ID, err)
		}
		decisionsByScan[s.ID] = ds
	}

	// Verify the audit hash chain for this tenant.
	chainRows, err := g.store.GetAuditChainRows(ctx, repo.InstallationID)
	if err != nil {
		return nil, fmt.Errorf("compliance: get audit chain: %w", err)
	}
	auditRows := make([]audit.ChainRow, len(chainRows))
	for i, r := range chainRows {
		auditRows[i] = audit.ChainRow{
			ID: r.ID, Ts: r.Ts, TenantID: r.TenantID,
			ActorGHID: r.ActorGHID, ActorLogin: r.ActorLogin,
			Repo: r.Repo, Action: r.Action, TargetID: r.TargetID,
			BeforeJSON: r.BeforeJSON, AfterJSON: r.AfterJSON,
			IP: r.IP, UserAgent: r.UserAgent,
			PrevHash: r.PrevHash, Hash: r.Hash,
		}
	}
	chainResult := audit.VerifyChain(auditRows)

	data := buildReportData(repoFullName, framework, since, scans, decisionsByScan, chainResult)

	hash, err := hashReportData(&data)
	if err != nil {
		return nil, fmt.Errorf("compliance: compute report hash: %w", err)
	}

	report := &Report{
		ReportHash:   hash,
		GenerationTs: time.Now().UTC(),
		TassVersion:  g.version,
		Data:         data,
	}

	if !chainResult.OK {
		return report, fmt.Errorf("%w: broken at event %s", ErrChainBroken, chainResult.BrokenAtID)
	}
	return report, nil
}

// buildReportData assembles the deterministic report payload.
func buildReportData(
	repoFullName, framework string,
	since *time.Time,
	scans []storage.ScanResult,
	decisionsByScan map[string][]storage.VerificationDecision,
	chain audit.VerifyResult,
) ReportData {
	fws := frameworksFor(framework)

	// Deduplicate capabilities: latest scan wins per capability ID.
	capMap := map[string]*capState{}

	for _, scan := range scans {
		ds := decisionsByScan[scan.ID]
		decisionByCapID := map[string]storage.VerificationDecision{}
		for _, d := range ds {
			decisionByCapID[d.CapabilityID] = d
		}

		for _, cap := range scan.Capabilities {
			existing, exists := capMap[cap.ID]
			if exists && !scan.ScannedAt.After(existing.scanTime) {
				continue
			}
			decision := "unconfirmed"
			var by string
			var at time.Time
			if d, ok := decisionByCapID[cap.ID]; ok {
				decision = string(d.Decision)
				by = d.DecidedBy
				at = d.DecidedAt
			}
			capMap[cap.ID] = &capState{
				cap:      cap,
				decision: decision,
				by:       by,
				at:       at,
				scanTime: scan.ScannedAt,
			}
		}
	}

	// Build sorted capability reports.
	capIDs := make([]string, 0, len(capMap))
	for id := range capMap {
		capIDs = append(capIDs, id)
	}
	sort.Strings(capIDs)

	var caps []CapabilityReport
	var unconfirmed []CapabilityReport
	confirmed, reverted, unconf := 0, 0, 0

	for _, id := range capIDs {
		cs := capMap[id]
		refs := controlRefsFor(cs.cap.Category, fws)
		cr := CapabilityReport{
			ID:          cs.cap.ID,
			Name:        cs.cap.Name,
			Category:    string(cs.cap.Category),
			Source:      string(cs.cap.Source),
			ConfirmedBy: cs.by,
			Decision:    cs.decision,
			ControlRefs: refs,
		}
		if !cs.at.IsZero() {
			cr.ConfirmedAt = cs.at.UTC().Format(time.RFC3339)
		}
		caps = append(caps, cr)
		switch cs.decision {
		case "confirmed":
			confirmed++
		case "reverted":
			reverted++
		default:
			unconf++
			unconfirmed = append(unconfirmed, cr)
		}
	}

	matrix := buildMatrix(capMap, capIDs, fws)
	tassControls := buildTassControls(fws)
	fwVersions := buildFrameworkVersions(fws)

	sinceStr := ""
	if since != nil {
		sinceStr = since.UTC().Format(time.RFC3339)
	}

	return ReportData{
		Repo:      repoFullName,
		Framework: framework,
		Since:     sinceStr,
		Summary: Summary{
			TotalScans:        len(scans),
			TotalCapabilities: len(capMap),
			ConfirmedCount:    confirmed,
			RevertedCount:     reverted,
			UnconfirmedCount:  unconf,
			AuditChainIntact:  chain.OK,
			ChainCheckedCount: chain.CheckedCount,
			ChainHeadHash:     chain.ChainHeadHash,
		},
		Capabilities:      caps,
		ControlMatrix:     matrix,
		Unconfirmed:       unconfirmed,
		TassControls:      tassControls,
		ChainAttestation:  ChainAttestation(chain),
		FrameworkVersions: fwVersions,
	}
}

func frameworksFor(framework string) []string {
	if framework == "all" {
		return FrameworkKeys()
	}
	return []string{framework}
}

func controlRefsFor(cat contracts.CapCategory, fws []string) []ControlRef {
	var refs []ControlRef
	for _, fw := range fws {
		for _, id := range ControlIDs(cat, fw) {
			refs = append(refs, ControlRef{Framework: fw, ControlID: id})
		}
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Framework != refs[j].Framework {
			return refs[i].Framework < refs[j].Framework
		}
		return refs[i].ControlID < refs[j].ControlID
	})
	return refs
}

func buildMatrix(capMap map[string]*capState, capIDs []string, fws []string) []ControlMatrixEntry {
	type entry struct {
		capIDs  []string
		hasEvid bool
	}
	matrix := map[string]*entry{}

	for _, id := range capIDs {
		cs := capMap[id]
		for _, fw := range fws {
			for _, ctrl := range ControlIDs(cs.cap.Category, fw) {
				key := fw + ":" + ctrl
				if matrix[key] == nil {
					matrix[key] = &entry{}
				}
				matrix[key].capIDs = append(matrix[key].capIDs, id)
				if cs.decision == "confirmed" {
					matrix[key].hasEvid = true
				}
			}
		}
	}

	keys := make([]string, 0, len(matrix))
	for k := range matrix {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]ControlMatrixEntry, 0, len(keys))
	for _, k := range keys {
		parts := strings.SplitN(k, ":", 2)
		e := matrix[k]
		sort.Strings(e.capIDs)
		out = append(out, ControlMatrixEntry{
			Framework:     parts[0],
			ControlID:     parts[1],
			CapabilityIDs: e.capIDs,
			HasEvidence:   e.hasEvid,
		})
	}
	return out
}

func buildTassControls(fws []string) []TassControlReport {
	entries := TassControlList()
	out := make([]TassControlReport, 0, len(entries))
	for _, tc := range entries {
		var refs []ControlRef
		for _, fw := range fws {
			for _, id := range tc.ControlsForFramework(fw) {
				refs = append(refs, ControlRef{Framework: fw, ControlID: id})
			}
		}
		sort.Slice(refs, func(i, j int) bool {
			if refs[i].Framework != refs[j].Framework {
				return refs[i].Framework < refs[j].Framework
			}
			return refs[i].ControlID < refs[j].ControlID
		})
		out = append(out, TassControlReport{
			Name:          tc.Name,
			ImplementedBy: tc.ImplementedBy,
			ControlRefs:   refs,
		})
	}
	return out
}

func buildFrameworkVersions(fws []string) []FrameworkVersion {
	out := make([]FrameworkVersion, 0, len(fws))
	for _, fw := range fws {
		out = append(out, FrameworkVersion{
			Key:       fw,
			Name:      FrameworkName(fw),
			Authority: FrameworkAuthority(fw),
		})
	}
	return out
}

// hashReportData produces a deterministic SHA-256 hash of the report payload.
// Covers ReportData only — not generation_ts or tass_version.
func hashReportData(data *ReportData) (string, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// --- Rendering ---

// ToJSON renders the report as indented JSON.
func (r *Report) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ToMarkdown renders the report as GitHub-flavored Markdown.
func (r *Report) ToMarkdown() string {
	var sb strings.Builder
	d := r.Data

	// Broken chain banner — must be prominent (spec: "fail loudly").
	if !d.ChainAttestation.OK {
		sb.WriteString("## ⚠ AUDIT CHAIN INTEGRITY FAILURE\n\n")
		sb.WriteString("> **WARNING:** The tamper-evident audit hash chain is broken.\n")
		sb.WriteString("> This report cannot be used as trustworthy compliance evidence.\n")
		if d.ChainAttestation.BrokenAtID != "" {
			fmt.Fprintf(&sb, "> First broken event ID: `%s`\n", d.ChainAttestation.BrokenAtID)
		}
		sb.WriteString("\n---\n\n")
	}

	// Title
	fwLabel := frameworkLabel(d.Framework, d.FrameworkVersions)
	fmt.Fprintf(&sb, "# TASS Compliance Report — %s\n\n", fwLabel)
	fmt.Fprintf(&sb, "**Repository:** `%s`  \n", d.Repo)
	if d.Since != "" {
		fmt.Fprintf(&sb, "**Since:** %s  \n", d.Since)
	}
	fmt.Fprintf(&sb, "**Generated:** %s  \n", r.GenerationTs.UTC().Format(time.RFC3339))
	fmt.Fprintf(&sb, "**TASS version:** %s  \n", r.TassVersion)
	fmt.Fprintf(&sb, "**Report hash:** `%s`  \n\n", r.ReportHash)

	// 1. Executive Summary
	sb.WriteString("## 1. Executive Summary\n\n")
	s := d.Summary
	fmt.Fprintf(&sb, "| Metric | Value |\n|---|---|\n")
	fmt.Fprintf(&sb, "| Total scans | %d |\n", s.TotalScans)
	fmt.Fprintf(&sb, "| Total capabilities | %d |\n", s.TotalCapabilities)
	fmt.Fprintf(&sb, "| Confirmed | %d |\n", s.ConfirmedCount)
	fmt.Fprintf(&sb, "| Reverted | %d |\n", s.RevertedCount)
	fmt.Fprintf(&sb, "| **Unconfirmed (residual risk)** | **%d** |\n", s.UnconfirmedCount)
	chainStatus := "✅ Intact"
	if !s.AuditChainIntact {
		chainStatus = "❌ BROKEN"
	}
	fmt.Fprintf(&sb, "| Audit chain | %s (%d events checked) |\n\n", chainStatus, s.ChainCheckedCount)

	// 2. Detected Capabilities
	sb.WriteString("## 2. Detected Capabilities\n\n")
	if len(d.Capabilities) == 0 {
		sb.WriteString("_No capabilities detected in the selected period._\n\n")
	} else {
		sb.WriteString("| ID | Name | Category | Source | Decision | Confirmed By | Control IDs |\n")
		sb.WriteString("|---|---|---|---|---|---|---|\n")
		for _, c := range d.Capabilities {
			ctrlStr := controlRefsSummary(c.ControlRefs)
			fmt.Fprintf(&sb, "| `%s` | %s | %s | %s | %s | %s | %s |\n",
				shortID(c.ID), c.Name, c.Category, c.Source, decisionBadge(c.Decision), c.ConfirmedBy, ctrlStr)
		}
		sb.WriteString("\n")
	}

	// 3. Control Coverage Matrix
	sb.WriteString("## 3. Control Coverage Matrix\n\n")
	if len(d.ControlMatrix) == 0 {
		sb.WriteString("_No capabilities mapped to controls._\n\n")
	} else {
		sb.WriteString("| Framework | Control ID | Evidence | Capability Count |\n")
		sb.WriteString("|---|---|---|---|\n")
		for _, e := range d.ControlMatrix {
			evid := "✅ Yes"
			if !e.HasEvidence {
				evid = "⚠ No confirmed"
			}
			fmt.Fprintf(&sb, "| %s | `%s` | %s | %d |\n",
				e.Framework, e.ControlID, evid, len(e.CapabilityIDs))
		}
		sb.WriteString("\n")
	}

	// 4. Unconfirmed Capabilities (Residual Risk)
	sb.WriteString("## 4. Unconfirmed Capabilities — Residual Risk\n\n")
	if len(d.Unconfirmed) == 0 {
		sb.WriteString("✅ All detected capabilities have been reviewed.\n\n")
	} else {
		sb.WriteString("> **ACTION REQUIRED:** The following capabilities have not been confirmed or reverted.\n\n")
		sb.WriteString("| ID | Name | Category | Control IDs |\n")
		sb.WriteString("|---|---|---|---|\n")
		for _, c := range d.Unconfirmed {
			fmt.Fprintf(&sb, "| `%s` | %s | %s | %s |\n",
				shortID(c.ID), c.Name, c.Category, controlRefsSummary(c.ControlRefs))
		}
		sb.WriteString("\n")
	}

	// 5. TASS Product Controls
	sb.WriteString("## 5. TASS Product Controls — Self-Attestation\n\n")
	sb.WriteString("| Control | Implemented By | Control IDs |\n")
	sb.WriteString("|---|---|---|\n")
	for _, tc := range d.TassControls {
		fmt.Fprintf(&sb, "| %s | `%s` | %s |\n",
			tc.Name, tc.ImplementedBy, controlRefsSummary(tc.ControlRefs))
	}
	sb.WriteString("\n")

	// 6. Audit Chain Attestation
	sb.WriteString("## 6. Audit Chain Attestation\n\n")
	ca := d.ChainAttestation
	if ca.OK {
		fmt.Fprintf(&sb, "✅ **Chain intact.** %d events verified.  \n", ca.CheckedCount)
		fmt.Fprintf(&sb, "**Chain head hash:** `%s`\n\n", ca.ChainHeadHash)
	} else {
		sb.WriteString("❌ **Chain BROKEN.**  \n")
		fmt.Fprintf(&sb, "**First broken event:** `%s`  \n", ca.BrokenAtID)
		sb.WriteString("This report must NOT be submitted as audit evidence.\n\n")
	}

	// 7. Framework Versions
	sb.WriteString("## 7. Framework Versions\n\n")
	sb.WriteString("| Key | Framework | Authority |\n")
	sb.WriteString("|---|---|---|\n")
	for _, fv := range d.FrameworkVersions {
		fmt.Fprintf(&sb, "| %s | %s | %s |\n", fv.Key, fv.Name, fv.Authority)
	}
	sb.WriteString("\n---\n\n")
	fmt.Fprintf(&sb, "_Report hash: `%s` · Generated %s · TASS %s_\n",
		r.ReportHash, r.GenerationTs.UTC().Format(time.RFC3339), r.TassVersion)

	return sb.String()
}

// ToPDF renders the report as PDF bytes.
// No external binaries or font files required — uses standard PDF Type1 core fonts.
func (r *Report) ToPDF() ([]byte, error) {
	return renderPDF(r)
}

// --- Markdown helpers ---

func frameworkLabel(framework string, versions []FrameworkVersion) string {
	if framework == "all" {
		return "All Frameworks"
	}
	for _, fv := range versions {
		if fv.Key == framework {
			return fv.Name
		}
	}
	return framework
}

func decisionBadge(d string) string {
	switch d {
	case "confirmed":
		return "Confirmed"
	case "reverted":
		return "Reverted"
	default:
		return "Unconfirmed"
	}
}

func shortID(id string) string {
	if len(id) > 40 {
		return id[:37] + "..."
	}
	return id
}

func controlRefsSummary(refs []ControlRef) string {
	if len(refs) == 0 {
		return "-"
	}
	parts := make([]string, len(refs))
	for i, r := range refs {
		parts[i] = r.ControlID
	}
	return strings.Join(parts, " ")
}
