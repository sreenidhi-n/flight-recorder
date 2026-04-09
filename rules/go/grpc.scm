; Detects gRPC client and server setup via google.golang.org/grpc.
; grpc.Dial() / grpc.NewClient() establishes an outbound gRPC connection.
; grpc.NewServer() creates a server that accepts inbound connections.
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @method)
  (#match? @pkg "^grpc$")
  (#match? @method "^(Dial|DialContext|NewClient|NewServer|Serve)$"))
