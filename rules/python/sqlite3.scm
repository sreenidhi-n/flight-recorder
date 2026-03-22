; Detects SQLite database connections via the sqlite3 standard library module.
; The @method capture provides the matched symbol for capability ID construction.
(call
  function: (attribute
    object: (identifier) @pkg
    attribute: (identifier) @method)
  (#match? @pkg "^sqlite3$")
  (#match? @method "^(connect|Connection)$"))
