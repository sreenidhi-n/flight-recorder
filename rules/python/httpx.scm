; Detects async/sync HTTP client calls via httpx — the modern alternative
; to requests used heavily in async Python services.
; Matches: httpx.get(), httpx.post(), httpx.Client(), httpx.AsyncClient()
(call
  function: (attribute
    object: (identifier) @pkg
    attribute: (identifier) @method)
  (#match? @pkg "^httpx$")
  (#match? @method "^(get|post|put|patch|delete|head|options|request|Client|AsyncClient|stream)$"))
