; Detects filesystem writes via Python's built-in open() function.
; Matches all open() calls — mode checking would require argument analysis
; which is beyond structural AST matching. Low false-positive risk in security contexts.
; The @func capture provides the matched symbol for capability ID construction.
(call
  function: (identifier) @func
  (#match? @func "^open$"))
