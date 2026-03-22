; Detects HTTP server creation in Node.js.
; Pattern 1: http.createServer() / https.createServer() — stdlib.
; Pattern 2: express() / fastify() / koa() — popular frameworks (direct calls).
; The @method capture provides the matched symbol for capability ID construction.

(call_expression
  function: (member_expression
    object: (identifier) @pkg
    property: (property_identifier) @method)
  (#match? @pkg "^(http|https)$")
  (#match? @method "^createServer$"))

(call_expression
  function: (identifier) @method
  (#match? @method "^(express|fastify|koa|hapi)$"))
