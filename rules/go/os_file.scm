; Detects filesystem operations via the os package: Create, Open, OpenFile,
; WriteFile, ReadFile, Remove, Rename, MkdirAll, Mkdir.
; The @method capture provides the matched symbol for capability ID construction.
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @method)
  (#match? @pkg "^os$")
  (#match? @method "^(Create|Open|OpenFile|WriteFile|ReadFile|Remove|RemoveAll|Rename|MkdirAll|Mkdir|Stat|Lstat)$"))
