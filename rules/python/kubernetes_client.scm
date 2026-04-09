; Detects Kubernetes cluster access via the official kubernetes Python client.
; Loading a kubeconfig or creating an API client means code can now
; create/delete/modify resources in a K8s cluster — a privilege_pattern.
;
; Matches: config.load_incluster_config(), config.load_kube_config(),
;          client.CoreV1Api(), client.AppsV1Api(), client.BatchV1Api(), etc.

; kubernetes.config.load_*_config()
(call
  function: (attribute
    object: (identifier) @pkg
    attribute: (identifier) @method)
  (#match? @pkg "^(config|kubernetes)$")
  (#match? @method "^(load_incluster_config|load_kube_config|load_kube_config_from_dict|new_client_from_config)$"))

; kubernetes.client.CoreV1Api(), AppsV1Api(), etc.
(call
  function: (attribute
    object: (identifier) @pkg
    attribute: (identifier) @cls)
  (#match? @pkg "^client$")
  (#match? @cls "^(CoreV1Api|AppsV1Api|BatchV1Api|NetworkingV1Api|RbacAuthorizationV1Api|CustomObjectsApi|ApiClient)$"))
