// Package mitigation generates deterministic infrastructure-as-code (IaC) and
// IAM snippets that mitigate novel capabilities flagged by a TASS contract check.
//
// Detection is based solely on the contract.Violation type — no AST scanning,
// no network calls, and no external templating dependencies are used.
// All templates use the standard library text/template package.
package mitigation

import "text/template"

// networkPolicySrc is a K8s NetworkPolicy that restricts egress to explicitly
// approved endpoints, generated for CatNetworkAccess violations.
const networkPolicySrc = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress-{{ .Slug }}
  namespace: default
  annotations:
    tass/capability-id: "{{ .CapabilityID }}"
    tass/violation-rule: "{{ .Rule }}"
spec:
  podSelector:
    matchLabels:
      app: <your-service-label>
  policyTypes:
    - Egress
  egress:
    # Allow DNS resolution (required for all outbound traffic)
    - ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    # Allow HTTPS to explicitly approved destinations only.
    # Replace ipBlock.cidr or add a namespaceSelector for internal services.
    - ports:
        - protocol: TCP
          port: 443
      to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.0.0/16  # link-local
              - 10.0.0.0/8      # RFC-1918 (remove if internal services needed)
              - 172.16.0.0/12
              - 192.168.0.0/16
  # All other egress is denied by the absence of a matching rule.`

// iamPolicySrc is an AWS IAM policy that applies least-privilege access for
// external API calls, generated for CatExternalAPI violations.
const iamPolicySrc = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TASSMitigationExternalAPI{{ .Slug }}",
      "Effect": "Allow",
      "Action": [
        "execute-api:Invoke"
      ],
      "Resource": [
        "arn:aws:execute-api:<region>:<account-id>:<api-id>/<stage>/<method>/<resource-path>"
      ],
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": "<region>"
        }
      }
    },
    {
      "Sid": "TASSMitigationDenyUnapprovedAPIs{{ .Slug }}",
      "Effect": "Deny",
      "NotAction": [
        "execute-api:Invoke"
      ],
      "Resource": "*"
    }
  ]
}`

// sqlGrantSrc is a SQL least-privilege script for CatDatabaseOp violations.
// Outputs ANSI SQL GRANT/REVOKE statements and a least-privilege checklist.
const sqlGrantSrc = `-- ============================================================
-- TASS Mitigation: least-privilege database access
-- Capability : {{ .CapabilityName }} ({{ .CapabilityID }})
-- Detected at: {{ .Location }}
-- Reason     : {{ .Reason }}
-- ============================================================

-- Step 1: Revoke all existing privileges on the relevant tables.
-- Replace <schema> and <table> with your actual schema/table names.
REVOKE ALL PRIVILEGES
  ON ALL TABLES IN SCHEMA <schema>
  FROM <app_user>;

-- Step 2: Grant only the minimum required access.
-- Start with SELECT; add INSERT/UPDATE only if explicitly required.
GRANT SELECT
  ON <schema>.<table>
  TO <app_user>;

-- Uncomment only the operations your application genuinely needs:
-- GRANT INSERT ON <schema>.<table> TO <app_user>;
-- GRANT UPDATE ON <schema>.<table> TO <app_user>;

-- Never grant DELETE, TRUNCATE, DROP, or ALTER unless a documented
-- security review explicitly approves it.

-- Step 3 (PostgreSQL): Verify effective permissions.
-- SELECT grantee, privilege_type FROM information_schema.role_table_grants
--   WHERE table_name = '<table>';`

// readOnlyFsSrc is a K8s Pod spec snippet enforcing a read-only root
// filesystem, generated for CatFileSystem violations.
const readOnlyFsSrc = `spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10000
    fsGroup: 10000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: <container-name>
      # Tass mitigation: capability "{{ .CapabilityName }}" detected at {{ .Location }}.
      # Enforce a read-only root filesystem to contain filesystem writes.
      securityContext:
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        runAsNonRoot: true
        runAsUser: 10000
        capabilities:
          drop:
            - ALL
      # If the application needs writable scratch space, mount an emptyDir.
      # Only mount the minimum paths your application writes to.
      volumeMounts:
        - name: tmp-dir
          mountPath: /tmp
        - name: cache-dir
          mountPath: /var/cache/<your-service>
  volumes:
    - name: tmp-dir
      emptyDir: {}
    - name: cache-dir
      emptyDir: {}`

// dropCapsSrc is a K8s Pod spec snippet that drops ALL Linux capabilities and
// sets allowPrivilegeEscalation: false, generated for CatPrivilege violations.
const dropCapsSrc = `spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10000
    fsGroup: 10000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: <container-name>
      # Tass mitigation: privilege pattern "{{ .CapabilityName }}" detected at {{ .Location }}.
      # Drop ALL Linux capabilities; grant back only what the application requires.
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 10000
        capabilities:
          drop:
            - ALL
          # Uncomment and list ONLY the capabilities your application requires:
          # add:
          #   - NET_BIND_SERVICE  # needed if binding to ports < 1024
          #   - CHOWN             # needed if the process changes file ownership`

// templates holds the parsed text/template for each capability category.
// Parsing is done at package initialisation so that template errors surface
// at startup, not at request time.
var templates = struct {
	NetworkPolicy *template.Template
	IAMPolicy     *template.Template
	SQLGrant      *template.Template
	ReadOnlyFS    *template.Template
	DropCaps      *template.Template
}{
	NetworkPolicy: template.Must(template.New("network_policy").Parse(networkPolicySrc)),
	IAMPolicy:     template.Must(template.New("iam_policy").Parse(iamPolicySrc)),
	SQLGrant:      template.Must(template.New("sql_grant").Parse(sqlGrantSrc)),
	ReadOnlyFS:    template.Must(template.New("readonly_fs").Parse(readOnlyFsSrc)),
	DropCaps:      template.Must(template.New("drop_caps").Parse(dropCapsSrc)),
}
