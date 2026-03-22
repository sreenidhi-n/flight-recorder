package scanner

import (
	"fmt"
	"sort"

	"github.com/tass-security/tass/pkg/contracts"
)

// DiffDependencies computes the set difference between two versions of a dependency
// file. It returns capabilities added in pr (not in base) and capabilities removed
// from base (not in pr).
//
// Nil base means the file is new in the PR — all pr capabilities are "added".
// Nil pr means the file was deleted in the PR — all base capabilities are "removed".
// Both nil returns empty slices with no error.
//
// The parser parameter determines which ecosystem is being diffed; this makes the
// function usable for go.mod, requirements.txt, package.json, etc. without changes.
// Results are sorted by ID for deterministic output.
func DiffDependencies(base, pr []byte, parser DepParser) (added, removed []contracts.Capability, err error) {
	var baseCaps, prCaps []contracts.Capability

	if base != nil {
		baseCaps, err = parser.ParseBytes(base)
		if err != nil {
			return nil, nil, fmt.Errorf("depdiff: parse base: %w", err)
		}
	}

	if pr != nil {
		prCaps, err = parser.ParseBytes(pr)
		if err != nil {
			return nil, nil, fmt.Errorf("depdiff: parse pr: %w", err)
		}
	}

	baseSet := indexByID(baseCaps)
	prSet := indexByID(prCaps)

	for id, cap := range prSet {
		if _, exists := baseSet[id]; !exists {
			added = append(added, cap)
		}
	}
	for id, cap := range baseSet {
		if _, exists := prSet[id]; !exists {
			removed = append(removed, cap)
		}
	}

	sort.Slice(added, func(i, j int) bool { return added[i].ID < added[j].ID })
	sort.Slice(removed, func(i, j int) bool { return removed[i].ID < removed[j].ID })

	return added, removed, nil
}

// indexByID builds a map from capability ID to capability for fast set-difference.
func indexByID(caps []contracts.Capability) map[string]contracts.Capability {
	m := make(map[string]contracts.Capability, len(caps))
	for _, c := range caps {
		m[c.ID] = c
	}
	return m
}
