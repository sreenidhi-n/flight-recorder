; Detects Strands AI agent usage — zero false positives via two complementary patterns.
;
; Pattern 1: qualified call   strands.Agent(system_prompt=..., model=...)
; Pattern 2: import boundary  from strands import Agent
;
; Both patterns capture @cls = "Agent", yielding a stable cap ID:
;   ast:python:strands:agent:Agent
;
; Rationale for using the import as a signal: `from strands import Agent` is an
; unambiguous declaration of Strands dependency at the module boundary. It has
; zero false positives — unlike matching bare Agent() calls which can collide
; with Agent classes from LangChain, AutoGen, or any other AI framework.

; Qualified form: strands.Agent(system_prompt=..., model=...)
(call
  function: (attribute
    object: (identifier) @pkg
    attribute: (identifier) @cls)
  (#match? @pkg "^strands$")
  (#match? @cls "^Agent$"))

; Import-from form: from strands import Agent
; The (dotted_name) @cls without a field name matches any dotted_name child of
; the import statement (including the module name), but the (#match? @pkg "^strands$")
; and (#match? @cls "^Agent$") predicates filter to only the intended match.
(import_from_statement
  module_name: (dotted_name) @pkg
  (dotted_name) @cls
  (#match? @pkg "^strands$")
  (#match? @cls "^Agent$"))
