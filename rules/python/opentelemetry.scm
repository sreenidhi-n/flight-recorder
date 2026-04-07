; Detects OpenTelemetry tracing setup — provider creation and installation.
; Matches: TracerProvider() constructor and *.set_tracer_provider() calls.
; The @func capture provides the matched symbol for capability ID construction.

; TracerProvider() constructor: provider = TracerProvider()
(call
  function: (identifier) @func
  (#match? @func "^TracerProvider$"))

; set_tracer_provider() call: trace.set_tracer_provider(provider)
(call
  function: (attribute
    object: (identifier)
    attribute: (identifier) @func)
  (#match? @func "^set_tracer_provider$"))
