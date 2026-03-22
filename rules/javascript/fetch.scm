; Detects HTTP client calls via fetch() and axios.
; Pattern 1: global fetch("url") — Web API / Node 18+.
; Pattern 2: axios.get/post/etc. — popular HTTP client library.
; The @method capture provides the matched symbol for capability ID construction.

(call_expression
  function: (identifier) @method
  (#match? @method "^fetch$"))

(call_expression
  function: (member_expression
    object: (identifier) @pkg
    property: (property_identifier) @method)
  (#match? @pkg "^axios$")
  (#match? @method "^(get|post|put|delete|head|patch|request|create)$"))
