; Detects direct AI provider SDK client instantiation.
; Covers OpenAI, Anthropic, Google Generative AI, Cohere, Mistral, and
; the AWS Bedrock runtime client (boto3 rule also covers boto3.client("bedrock-runtime")).
;
; These are external_api capabilities — code gains ability to call a
; proprietary AI model API and send arbitrary prompts.

; openai.OpenAI(), openai.AzureOpenAI(), openai.AsyncOpenAI()
(call
  function: (attribute
    object: (identifier) @pkg
    attribute: (identifier) @cls)
  (#match? @pkg "^openai$")
  (#match? @cls "^(OpenAI|AzureOpenAI|AsyncOpenAI|AsyncAzureOpenAI)$"))

; anthropic.Anthropic(), anthropic.AsyncAnthropic()
(call
  function: (attribute
    object: (identifier) @pkg
    attribute: (identifier) @cls)
  (#match? @pkg "^anthropic$")
  (#match? @cls "^(Anthropic|AsyncAnthropic|AnthropicBedrock|AnthropicVertex)$"))

; google.generativeai.GenerativeModel() — qualified
(call
  function: (attribute
    object: (attribute
      object: (identifier) @pkg)
    attribute: (identifier) @cls)
  (#match? @pkg "^google$")
  (#match? @cls "^GenerativeModel$"))

; genai.GenerativeModel() — common import alias
(call
  function: (attribute
    object: (identifier) @pkg
    attribute: (identifier) @cls)
  (#match? @pkg "^genai$")
  (#match? @cls "^(GenerativeModel|configure)$"))

; cohere.Client(), cohere.AsyncClient()
(call
  function: (attribute
    object: (identifier) @pkg
    attribute: (identifier) @cls)
  (#match? @pkg "^cohere$")
  (#match? @cls "^(Client|AsyncClient)$"))
