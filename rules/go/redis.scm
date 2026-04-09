; Detects Redis client creation via go-redis (github.com/redis/go-redis).
; redis.NewClient(), redis.NewClusterClient(), redis.NewFailoverClient()
; establish a connection to a Redis instance.
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @method)
  (#match? @pkg "^redis$")
  (#match? @method "^(NewClient|NewClusterClient|NewFailoverClient|NewRing|NewUniversalClient|NewSentinelClient)$"))
