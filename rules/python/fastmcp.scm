; Detects FastMCP server creation and tool/resource/prompt registration.
; Matches: FastMCP(...) constructor and @mcp.tool() / @mcp.resource() / @mcp.prompt() decorators.
; The @cls capture provides the matched symbol for capability ID construction.

; FastMCP() constructor: mcp = FastMCP(name="...", instructions="...")
(call
  function: (identifier) @cls
  (#match? @cls "^FastMCP$"))

; @mcp.tool() / @mcp.resource() / @mcp.prompt() decorator applied to a function
(decorator
  (call
    function: (attribute
      object: (identifier)
      attribute: (identifier) @cls)
    (#match? @cls "^(tool|resource|prompt)$")))
