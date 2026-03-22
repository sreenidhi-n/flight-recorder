; Detects filesystem operations via Node.js fs module.
; Matches both callback and sync variants.
; The @method capture provides the matched symbol for capability ID construction.
(call_expression
  function: (member_expression
    object: (identifier) @pkg
    property: (property_identifier) @method)
  (#match? @pkg "^fs$")
  (#match? @method "^(writeFile|readFile|appendFile|writeFileSync|readFileSync|appendFileSync|unlink|unlinkSync|mkdir|mkdirSync|rmdir|rmdirSync|rename|renameSync|copyFile|copyFileSync)$"))
