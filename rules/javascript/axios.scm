; Detects HTTP calls via axios — one of the most common Node.js HTTP clients.
; Matches: axios.get(), axios.post(), axios.put(), axios.delete(),
;          axios.request(), axios.create(), axios(config)
(call_expression
  function: (member_expression
    object: (identifier) @pkg
    property: (property_identifier) @method)
  (#match? @pkg "^axios$")
  (#match? @method "^(get|post|put|patch|delete|head|options|request|create)$"))

; axios(config) — direct call as a function
(call_expression
  function: (identifier) @func
  (#match? @func "^axios$"))
