package templates

import (
	"sort"
	"strings"

	"github.com/tass-security/tass/internal/storage"
)

// BlastRadiusGraph holds all pre-computed data needed to render the SVG blast-
// radius view.  Positions are calculated server-side; the template emits a
// static inline SVG with no JavaScript.
type BlastRadiusGraph struct {
	SVGWidth  int
	SVGHeight int
	RepoNodes []BRNode
	CapNodes  []BRNode
	Edges     []BREdge
	Empty     bool
}

// BRNode is a single labelled circle in the SVG.
type BRNode struct {
	ID    string // unique key used to look up edges
	Label string // display text (possibly truncated)
	X, Y  int    // centre of the circle
	Color string // CSS hex colour
	Count int    // number of incident edges
}

// BREdge is a single line in the SVG connecting a repo node to a cap node.
type BREdge struct {
	X1, Y1 int
	X2, Y2 int
	Color  string
	Width  int // stroke-width in pixels
}

// categoryColor maps a capability category string to a hex fill colour that
// matches the design-system badge pills defined in style.css.
func categoryColor(cat string) string {
	switch strings.ToLower(cat) {
	case "external_dependency":
		return "#7c3aed"
	case "network_access", "external_api":
		return "#2563eb"
	case "database_operation":
		return "#d97706"
	case "filesystem_operation":
		return "#16a34a"
	case "privilege_pattern":
		return "#dc2626"
	default:
		return "#6b7280"
	}
}

// MitRowID converts a capability ID into a stable, CSS-selector-safe HTML element
// ID that can be used as both the <div id="…"> in the table row and the
// hx-target="#…" in the mitigation handler response.
// Example: "ast:go:net/http:Client.Do" → "mit-ast-go-net-http-client-do"
func MitRowID(capID string) string {
	var b strings.Builder
	prev := false
	for _, r := range strings.ToLower(capID) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prev = false
		} else if !prev {
			b.WriteRune('-')
			prev = true
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		s = "cap"
	}
	return "mit-" + s
}

// truncate returns s shortened to at most n runes with a "…" suffix.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// BuildBlastRadius constructs a BlastRadiusGraph from a slice of confirmed
// capabilities.  The layout uses a bipartite graph: repositories on the left,
// unique capability endpoints on the right.  Node Y-positions are distributed
// evenly; X-positions are fixed constants suitable for a 760-wide viewport.
func BuildBlastRadius(caps []storage.ConfirmedCapability) BlastRadiusGraph {
	if len(caps) == 0 {
		return BlastRadiusGraph{Empty: true, SVGWidth: 760, SVGHeight: 160}
	}

	// --- Collect unique repos ---
	repoOrder := []string{}
	repoSeen := map[string]bool{}
	for _, c := range caps {
		if !repoSeen[c.RepoFullName] {
			repoSeen[c.RepoFullName] = true
			repoOrder = append(repoOrder, c.RepoFullName)
		}
	}
	sort.Strings(repoOrder)

	// --- Collect unique capabilities (by Name+Category, deduplicated) ---
	type capKey struct{ name, category string }
	capOrder := []capKey{}
	capSeen := map[capKey]bool{}
	for _, c := range caps {
		k := capKey{c.Name, c.Category}
		if !capSeen[k] {
			capSeen[k] = true
			capOrder = append(capOrder, k)
		}
	}
	// Sort by category then name for a stable layout
	sort.Slice(capOrder, func(i, j int) bool {
		if capOrder[i].category != capOrder[j].category {
			return capOrder[i].category < capOrder[j].category
		}
		return capOrder[i].name < capOrder[j].name
	})

	// --- Layout constants ---
	const (
		svgWidth    = 760
		paddingY    = 36
		rowHeight   = 44
		repoCircleX = 80
		capCircleX  = 670
		// Line endpoints are inset a few pixels from the circle centres
		lineStartX = 96
		lineEndX   = 654
	)

	totalRows := len(repoOrder)
	if len(capOrder) > totalRows {
		totalRows = len(capOrder)
	}
	svgHeight := totalRows*rowHeight + 2*paddingY

	repoYMap := map[string]int{}
	repoNodes := make([]BRNode, len(repoOrder))
	for i, name := range repoOrder {
		y := paddingY + i*rowHeight + rowHeight/2
		repoYMap[name] = y
		repoNodes[i] = BRNode{
			ID:    name,
			Label: truncate(name, 26),
			X:     repoCircleX,
			Y:     y,
			Color: "#64748b",
		}
	}

	capYMap := map[capKey]int{}
	capNodes := make([]BRNode, len(capOrder))
	for i, k := range capOrder {
		y := paddingY + i*rowHeight + rowHeight/2
		capYMap[k] = y
		capNodes[i] = BRNode{
			ID:    k.name + "/" + k.category,
			Label: truncate(k.name, 26),
			X:     capCircleX,
			Y:     y,
			Color: categoryColor(k.category),
		}
	}

	// --- Build edges ---
	type edgeKey struct {
		repo    string
		capName string
		capCat  string
	}
	edgeSeen := map[edgeKey]bool{}
	var edges []BREdge
	for _, c := range caps {
		ek := edgeKey{c.RepoFullName, c.Name, c.Category}
		if edgeSeen[ek] {
			continue
		}
		edgeSeen[ek] = true
		ry := repoYMap[c.RepoFullName]
		k := capKey{c.Name, c.Category}
		cy := capYMap[k]
		color := categoryColor(c.Category)
		edges = append(edges, BREdge{
			X1:    lineStartX,
			Y1:    ry,
			X2:    lineEndX,
			Y2:    cy,
			Color: color,
			Width: 1,
		})
		// Increment connection count on the nodes
		for i := range repoNodes {
			if repoNodes[i].ID == c.RepoFullName {
				repoNodes[i].Count++
			}
		}
		capKey2 := c.Name + "/" + c.Category
		for i := range capNodes {
			if capNodes[i].ID == capKey2 {
				capNodes[i].Count++
				// Thicken edge if cap is shared across many repos
				if capNodes[i].Count > 1 {
					edges[len(edges)-1].Width = 2
				}
			}
		}
	}

	return BlastRadiusGraph{
		SVGWidth:  svgWidth,
		SVGHeight: svgHeight,
		RepoNodes: repoNodes,
		CapNodes:  capNodes,
		Edges:     edges,
	}
}
