; Detects external process execution via os/exec package.
; exec.Command and exec.CommandContext initiate subprocess execution,
; which is a privilege pattern worth flagging for review.
; The @method capture provides the matched symbol for capability ID construction.
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @method)
  (#match? @pkg "^exec$")
  (#match? @method "^(Command|CommandContext)$"))
