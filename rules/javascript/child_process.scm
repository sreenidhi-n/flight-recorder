; Detects shell execution via Node.js child_process module.
; exec(), spawn(), fork(), execFile() gain the ability to run arbitrary
; OS commands — a high-confidence privilege pattern.
;
; Matches method calls on any object (commonly the destructured import):
;   const { exec } = require('child_process'); exec("cmd")
;   cp.exec("cmd"), child_process.spawn("cmd")
(call_expression
  function: (member_expression
    object: (identifier) @obj
    property: (property_identifier) @method)
  (#match? @method "^(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)$"))

; Direct calls after destructuring: exec("cmd"), spawn("ls")
(call_expression
  function: (identifier) @func
  (#match? @func "^(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)$"))
