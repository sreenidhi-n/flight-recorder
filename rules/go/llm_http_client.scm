; Detects outbound HTTP calls (via net/http) whose first string-literal argument
; contains a known LLM provider API hostname.  The #match? predicate on @url
; filters to calls like: http.Get("https://api.openai.com/v1/...").
;
; Only direct string literals are matched — variables that hold LLM URLs are NOT
; caught here (they are caught by the ai_clients rule for SDK instantiation).
; The @method capture drives the capability ID, keeping it stable per call site.
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @method)
  arguments: (argument_list
    (interpreted_string_literal) @url)
  (#match? @pkg "^http$")
  (#match? @method "^(Get|Post|Put|Delete|Head|Do|PostForm|NewRequest|NewRequestWithContext)$")
  (#match? @url "(api\\.openai\\.com|api\\.anthropic\\.com|generativelanguage\\.googleapis\\.com|api\\.cohere\\.ai|api\\.mistral\\.ai|bedrock\\.amazonaws\\.com|openrouter\\.ai|api\\.together\\.ai|api\\.replicate\\.com|api\\.groq\\.com|api\\.perplexity\\.ai|inference\\.huggingface\\.co)"))
