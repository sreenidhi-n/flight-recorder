; Detects Strands AI agent instantiation.
; Matches the qualified form (strands.Agent(...)) and the import-from form
; (Agent(...) after `from strands import Agent`). Both are deduplicated by
; cap_id so a file using either form produces exactly one capability.
; The @cls capture provides the matched symbol for capability ID construction.

; Qualified form: strands.Agent(system_prompt=..., model=...)
(call
  function: (attribute
    object: (identifier) @pkg
    attribute: (identifier) @cls)
  (#match? @pkg "^strands$")
  (#match? @cls "^Agent$"))

; Import-from form: Agent(...) after `from strands import Agent`
; Note: may produce false positives if a non-Strands Agent class is in scope.
(call
  function: (identifier) @cls
  (#match? @cls "^Agent$"))
