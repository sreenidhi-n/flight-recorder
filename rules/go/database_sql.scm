; Detects database/sql usage in Go.
; Pattern 1: sql.Open() — high-confidence package match.
; Pattern 2: db.Query/Exec variants — method-name match (pkg is a variable, not importable).
; The @method capture provides the matched symbol for capability ID construction.

(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @method)
  (#match? @pkg "^sql$")
  (#match? @method "^Open$"))

(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @method)
  (#match? @method "^(Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Prepare|PrepareContext)$"))
