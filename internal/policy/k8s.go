// Package policy generates security policy artifacts from a TASS manifest.
// Supported outputs: Kubernetes NetworkPolicy YAML, AWS IAM Policy JSON.
package policy

import (
	"bytes"
	"strings"
	"text/template"
	"time"

	"github.com/tass-security/tass/pkg/contracts"
	"github.com/tass-security/tass/pkg/manifest"
)

// PolicyOpts controls how policies are generated.
type PolicyOpts struct {
	AppName   string // used in podSelector matchLabels: app: <AppName>
	Namespace string // Kubernetes namespace, defaults to "default"
}

// networkPolicyData is the template input for k8s network policy generation.
type networkPolicyData struct {
	AppName     string
	Namespace   string
	GeneratedAt string
	NetCaps     []capEntry
}

type capEntry struct {
	Name     string
	Category string
}

const netpolTmpl = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ .AppName }}-tass-netpol
  namespace: {{ .Namespace }}
  annotations:
    tass.dev/generated-from: "tass.manifest.yaml"
    tass.dev/generated-at: "{{ .GeneratedAt }}"
spec:
  podSelector:
    matchLabels:
      app: {{ .AppName }}
  policyTypes:
    - Egress
  egress:
    # DNS — required for service discovery and name resolution
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
{{- if .NetCaps }}
    # HTTPS egress — detected network capabilities:
{{- range .NetCaps }}
    #   {{ .Name }} ({{ .Category }})
{{- end }}
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - port: 443
          protocol: TCP
{{- end }}
`

// GenerateNetworkPolicy creates a Kubernetes NetworkPolicy YAML from a manifest.
// Capabilities with category network_access or external_api produce egress rules.
// A DNS egress rule is always included regardless of capabilities.
func GenerateNetworkPolicy(m *manifest.Manifest, opts PolicyOpts) ([]byte, error) {
	if opts.Namespace == "" {
		opts.Namespace = "default"
	}
	if opts.AppName == "" {
		opts.AppName = "myapp"
	}

	// Deduplicate network/API capabilities.
	seen := make(map[string]bool)
	var netCaps []capEntry
	for _, cap := range m.Capabilities {
		if cap.Category != contracts.CatNetworkAccess && cap.Category != contracts.CatExternalAPI {
			continue
		}
		key := strings.ToLower(cap.Name)
		if seen[key] {
			continue
		}
		seen[key] = true
		netCaps = append(netCaps, capEntry{
			Name:     cap.Name,
			Category: string(cap.Category),
		})
	}

	data := networkPolicyData{
		AppName:     opts.AppName,
		Namespace:   opts.Namespace,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		NetCaps:     netCaps,
	}

	t, err := template.New("netpol").Parse(netpolTmpl)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
