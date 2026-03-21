// Package contracts defines the shared types used across all TASS packages.
// These types are the single source of truth for capability representation,
// scan output, and verification decisions.
package contracts

import "time"

// CapCategory represents the kind of capability detected.
type CapCategory string

const (
	CatExternalDep   CapCategory = "external_dependency"
	CatExternalAPI   CapCategory = "external_api"
	CatDatabaseOp    CapCategory = "database_operation"
	CatNetworkAccess CapCategory = "network_access"
	CatFileSystem    CapCategory = "filesystem_operation"
	CatPrivilege     CapCategory = "privilege_pattern"
)

// DetectionLayer identifies which scanner layer produced a capability.
type DetectionLayer string

const (
	LayerDependency DetectionLayer = "layer0_dependency"
	LayerAST        DetectionLayer = "layer1_ast"
)

// CodeLocation records where in the source a capability was detected.
type CodeLocation struct {
	File   string `json:"file" yaml:"file"`
	Line   int    `json:"line,omitempty" yaml:"line,omitempty"`
	Column int    `json:"column,omitempty" yaml:"column,omitempty"`
}

// Capability is a single detected capability. IDs must be deterministic:
// derived from (category + source_identifier + canonical_name), never
// from line numbers or file offsets.
type Capability struct {
	ID          string         `json:"id" yaml:"id"`
	Name        string         `json:"name" yaml:"name"`
	Category    CapCategory    `json:"category" yaml:"category"`
	Source      DetectionLayer `json:"source" yaml:"source"`
	Location    CodeLocation   `json:"location" yaml:"location"`
	Confidence  float64        `json:"confidence" yaml:"confidence"`
	RawEvidence string         `json:"raw_evidence" yaml:"raw_evidence"`
}

// CapabilitySet is the complete output of a scan run.
type CapabilitySet struct {
	RepoRoot     string       `json:"repo_root"`
	ScanTime     time.Time    `json:"scan_time"`
	CommitSHA    string       `json:"commit_sha,omitempty"`
	Capabilities []Capability `json:"capabilities"`
}

// VerificationDecision is a developer's confirm/revert choice.
type VerificationDecision string

const (
	DecisionConfirm VerificationDecision = "confirm"
	DecisionRevert  VerificationDecision = "revert"
)

// VerificationReceipt records a developer's decision about a capability.
type VerificationReceipt struct {
	CapabilityID  string               `json:"capability_id"`
	Decision      VerificationDecision `json:"decision"`
	Justification string               `json:"justification,omitempty"`
	DecidedBy     string               `json:"decided_by"`
	DecidedAt     time.Time            `json:"decided_at"`
}
