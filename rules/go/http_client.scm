; Detects outbound HTTP client calls via net/http: http.Get, http.Post,
; http.Put, http.Delete, http.Head, http.Do, http.PostForm.
; The @method capture provides the matched symbol for capability ID construction.
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @method)
  (#match? @pkg "^http$")
  (#match? @method "^(Get|Post|Put|Delete|Head|Do|PostForm)$"))
