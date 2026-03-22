; Detects HTTP client calls via the requests library.
; Matches: requests.get(), requests.post(), requests.put(), requests.delete(),
;          requests.head(), requests.patch(), requests.request()
; The @method capture provides the matched symbol for capability ID construction.
(call
  function: (attribute
    object: (identifier) @pkg
    attribute: (identifier) @method)
  (#match? @pkg "^requests$")
  (#match? @method "^(get|post|put|delete|head|patch|options|request)$"))
