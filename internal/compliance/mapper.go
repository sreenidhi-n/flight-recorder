// Package compliance maps detected TASS capabilities to compliance control IDs
// and generates evidence reports for SOC 2, ISO 27001, and NIST 800-53.
//
// # Framework versions (LOCKED — do not change control IDs without re-verifying source docs)
//
//	SOC 2:      AICPA TSP Section 100 (2017 TSC w/ 2022 Revised Points of Focus)
//	ISO 27001:  ISO/IEC 27001:2022 Annex A
//	NIST 80053: NIST SP 800-53 Rev 5 (Dec 2020 errata, 5.2.0 updates)
package compliance

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tass-security/tass/pkg/contracts"
)

//go:embed frameworks.yaml
var frameworksYAML []byte

// FrameworkInfo describes a compliance framework.
type FrameworkInfo struct {
	Name      string `yaml:"name"`
	Authority string `yaml:"authority"`
}

// CategoryMapping maps a capability category to per-framework control IDs.
// The YAML key "city_mappings" is locked per spec — do not rename.
type CategoryMapping struct {
	Description string   `yaml:"description"`
	SOC2        []string `yaml:"soc2"`
	ISO27001    []string `yaml:"iso27001"`
	NIST80053   []string `yaml:"nist80053"`
}

// TassControl describes a control that TASS itself implements (self-attestation).
type TassControl struct {
	ImplementedBy string   `yaml:"implemented_by"`
	SOC2          []string `yaml:"soc2"`
	ISO27001      []string `yaml:"iso27001"`
	NIST80053     []string `yaml:"nist80053"`
}

// FrameworksFile is the root of frameworks.yaml.
type FrameworksFile struct {
	Frameworks   map[string]FrameworkInfo   `yaml:"frameworks"`
	CityMappings map[string]CategoryMapping `yaml:"city_mappings"` // LOCKED key
	TassControls map[string]TassControl     `yaml:"tass_product_controls"`
}

var (
	loaded    *FrameworksFile
	loadedErr error
)

func init() {
	loaded, loadedErr = parse()
}

func parse() (*FrameworksFile, error) {
	var f FrameworksFile
	if err := yaml.Unmarshal(frameworksYAML, &f); err != nil {
		return nil, fmt.Errorf("compliance: parse frameworks.yaml: %w", err)
	}
	return &f, nil
}

// Load returns the parsed frameworks configuration.
// Panics if the embedded YAML is malformed — indicates a corrupt binary.
func Load() *FrameworksFile {
	if loadedErr != nil {
		panic("compliance: frameworks.yaml malformed in binary: " + loadedErr.Error())
	}
	return loaded
}

// catToMappingKey maps contracts.CapCategory to the city_mappings key in frameworks.yaml.
// The YAML uses shorter category keys that differ from contracts.CapCategory values.
func catToMappingKey(cat contracts.CapCategory) string {
	switch cat {
	case contracts.CatNetworkAccess:
		return "network_access"
	case contracts.CatPrivilege:
		return "privilege_escalation"
	case contracts.CatExternalDep:
		return "dependency"
	case contracts.CatDatabaseOp:
		return "database"
	case contracts.CatFileSystem:
		return "filesystem"
	case contracts.CatExternalAPI:
		return "external_api"
	default:
		return string(cat)
	}
}

// ControlIDs returns the sorted list of control IDs for the given capability
// category and framework key ("soc2", "iso27001", or "nist80053").
// Returns nil for unknown categories or frameworks.
func ControlIDs(cat contracts.CapCategory, framework string) []string {
	f := Load()
	m, ok := f.CityMappings[catToMappingKey(cat)]
	if !ok {
		return nil
	}
	var ids []string
	switch strings.ToLower(framework) {
	case "soc2":
		ids = m.SOC2
	case "iso27001":
		ids = m.ISO27001
	case "nist80053":
		ids = m.NIST80053
	}
	out := make([]string, len(ids))
	copy(out, ids)
	sort.Strings(out)
	return out
}

// AllControlIDs returns control IDs for all three frameworks.
func AllControlIDs(cat contracts.CapCategory) map[string][]string {
	return map[string][]string{
		"soc2":      ControlIDs(cat, "soc2"),
		"iso27001":  ControlIDs(cat, "iso27001"),
		"nist80053": ControlIDs(cat, "nist80053"),
	}
}

// FrameworkKeys returns the canonical set of framework keys.
func FrameworkKeys() []string {
	return []string{"soc2", "iso27001", "nist80053"}
}

// FrameworkName returns the display name for a framework key.
func FrameworkName(key string) string {
	f := Load()
	if fw, ok := f.Frameworks[key]; ok {
		return fw.Name
	}
	return key
}

// FrameworkAuthority returns the issuing authority for a framework key.
func FrameworkAuthority(key string) string {
	f := Load()
	if fw, ok := f.Frameworks[key]; ok {
		return fw.Authority
	}
	return ""
}

// TassControlList returns the TASS self-attestation controls in sorted order.
func TassControlList() []TassControlEntry {
	f := Load()
	keys := make([]string, 0, len(f.TassControls))
	for k := range f.TassControls {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]TassControlEntry, 0, len(keys))
	for _, k := range keys {
		tc := f.TassControls[k]
		out = append(out, TassControlEntry{
			Name:          k,
			ImplementedBy: tc.ImplementedBy,
			SOC2:          sorted(tc.SOC2),
			ISO27001:      sorted(tc.ISO27001),
			NIST80053:     sorted(tc.NIST80053),
		})
	}
	return out
}

// TassControlEntry is a resolved TASS self-attestation control.
type TassControlEntry struct {
	Name          string
	ImplementedBy string
	SOC2          []string
	ISO27001      []string
	NIST80053     []string
}

// ControlsForFramework returns the control IDs for a TassControlEntry for a given framework.
func (t TassControlEntry) ControlsForFramework(fw string) []string {
	switch fw {
	case "soc2":
		return t.SOC2
	case "iso27001":
		return t.ISO27001
	case "nist80053":
		return t.NIST80053
	}
	return nil
}

func sorted(ss []string) []string {
	out := make([]string, len(ss))
	copy(out, ss)
	sort.Strings(out)
	return out
}
