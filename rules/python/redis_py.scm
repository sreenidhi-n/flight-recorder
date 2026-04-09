; Detects Redis connections via the redis-py client.
; redis.Redis(), redis.StrictRedis(), redis.asyncio.Redis(), redis.from_url()
(call
  function: (attribute
    object: (identifier) @pkg
    attribute: (identifier) @cls)
  (#match? @pkg "^redis$")
  (#match? @cls "^(Redis|StrictRedis|ConnectionPool|from_url|Sentinel)$"))

; redis.asyncio.Redis()
(call
  function: (attribute
    object: (attribute
      object: (identifier) @pkg)
    attribute: (identifier) @cls)
  (#match? @pkg "^redis$")
  (#match? @cls "^(Redis|ConnectionPool|from_url)$"))
