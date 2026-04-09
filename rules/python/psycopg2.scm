; Detects PostgreSQL database connections via psycopg2 / psycopg3.
; psycopg2.connect() and psycopg.connect() establish a live DB connection.
(call
  function: (attribute
    object: (identifier) @pkg
    attribute: (identifier) @method)
  (#match? @pkg "^(psycopg2|psycopg|psycopg3)$")
  (#match? @method "^(connect|AsyncConnection|AsyncClientCursor)$"))

; Also catches: from psycopg2 import connect; connect(...)
(call
  function: (identifier) @func
  (#match? @func "^connect$"))
