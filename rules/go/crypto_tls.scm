; Detects custom TLS configuration in Go via the crypto/tls package.
; tls.Config{} struct literals and tls.X509KeyPair() / tls.LoadX509KeyPair()
; indicate code is managing its own certificate/TLS setup — a privilege pattern
; worth reviewing (InsecureSkipVerify, custom root CAs, client auth, etc.).
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @method)
  (#match? @pkg "^tls$")
  (#match? @method "^(X509KeyPair|LoadX509KeyPair|NewListener|NewClientConn|NewServerConn|Dial|DialWithDialer|Server|Client)$"))
