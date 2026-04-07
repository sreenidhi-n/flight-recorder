; Detects AWS SDK service connections via boto3.
; Matches: boto3.client("s3"), boto3.resource("dynamodb"), etc.
; The @method capture provides the matched symbol for capability ID construction.
(call
  function: (attribute
    object: (identifier) @pkg
    attribute: (identifier) @method)
  (#match? @pkg "^boto3$")
  (#match? @method "^(client|resource)$"))
