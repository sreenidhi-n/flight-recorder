; Detects network listener/dialer operations via the net package:
; net.Listen, net.ListenTCP, net.ListenUDP, net.Dial, net.DialTCP, net.DialUDP.
; The @method capture provides the matched symbol for capability ID construction.
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @method)
  (#match? @pkg "^net$")
  (#match? @method "^(Listen|ListenTCP|ListenUDP|ListenUnix|Dial|DialTCP|DialUDP|DialUnix|LookupHost|LookupIP)$"))
