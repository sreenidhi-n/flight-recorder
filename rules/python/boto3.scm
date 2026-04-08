; Detects AWS SDK service connections via boto3.
; Matches: boto3.client("s3"), boto3.resource("dynamodb"), etc.
;
; @service captures the string content of the first positional argument so that
; boto3.client("s3") and boto3.client("bedrock-runtime") produce distinct
; capability IDs (ast:python:boto3:client:s3 vs ast:python:boto3:client:bedrock-runtime).
; Calls with a variable service name (e.g. boto3.client(svc)) are caught by the
; fallback pattern below, which uses the method name as the symbol instead.

; Primary: boto3.client("service-name") — captures the string literal
(call
  function: (attribute
    object: (identifier) @pkg
    attribute: (identifier) @method)
  arguments: (argument_list
    (string
      (string_content) @service))
  (#match? @pkg "^boto3$")
  (#match? @method "^(client|resource)$"))
