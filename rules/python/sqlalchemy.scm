; Detects database engine/session creation via SQLAlchemy ORM.
; create_engine() establishes a DB connection pool — the primary signal
; that code can now reach a relational database.
; Matches: create_engine(), create_async_engine(), sessionmaker()

; create_engine("postgresql://...") — direct call, commonly imported as
; `from sqlalchemy import create_engine`
(call
  function: (identifier) @func
  (#match? @func "^(create_engine|create_async_engine|sessionmaker|async_sessionmaker)$"))

; sqlalchemy.create_engine() — qualified call
(call
  function: (attribute
    object: (identifier) @pkg
    attribute: (identifier) @method)
  (#match? @pkg "^(sqlalchemy|sa)$")
  (#match? @method "^(create_engine|create_async_engine|sessionmaker)$"))
