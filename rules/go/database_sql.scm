; Detects database/sql usage in Go.
;
; Pattern 1: sql.Open() — clear package-qualified call, high confidence.
;
; Note: db.Query(), db.Exec() etc. are NOT matched here because the receiver
; variable name is not the package name — it could be any identifier (db, conn,
; cursor, etc.), and matching on method name alone produces too many false
; positives (e.g. tree-sitter's cursor.Exec). Detection of query/exec calls
; is deferred until type-aware analysis is available in a future layer.
;
; The @method capture provides the matched symbol for capability ID construction.

(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @method)
  (#match? @pkg "^sql$")
  (#match? @method "^(Open|OpenDB)$"))
