; Detects database client instantiation in Node.js.
; Covers PostgreSQL (pg), MySQL (mysql2), MongoDB (mongoose/mongodb),
; and Redis (ioredis/redis).

; new Client() / new Pool() from pg (PostgreSQL)
(new_expression
  constructor: (identifier) @cls
  (#match? @cls "^(Client|Pool)$"))

; mysql.createConnection(), mysql.createPool() — mysql / mysql2
(call_expression
  function: (member_expression
    object: (identifier) @pkg
    property: (property_identifier) @method)
  (#match? @pkg "^(mysql|mysql2)$")
  (#match? @method "^(createConnection|createPool|createPoolCluster)$"))

; mongoose.connect(), mongoose.createConnection()
(call_expression
  function: (member_expression
    object: (identifier) @pkg
    property: (property_identifier) @method)
  (#match? @pkg "^mongoose$")
  (#match? @method "^(connect|createConnection|model)$"))

; new MongoClient() — mongodb driver
(new_expression
  constructor: (identifier) @cls
  (#match? @cls "^MongoClient$"))

; new Redis() / new IORedis() — ioredis
(new_expression
  constructor: (identifier) @cls
  (#match? @cls "^(Redis|IORedis|Cluster)$"))
