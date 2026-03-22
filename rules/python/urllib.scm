; Detects HTTP calls via urllib.request: urllib.request.urlopen(), urlretrieve().
; The attribute chain is: urllib -> request -> urlopen/urlretrieve.
; The @method capture provides the matched symbol for capability ID construction.
(call
  function: (attribute
    object: (attribute
      object: (identifier) @pkg)
    attribute: (identifier) @method)
  (#match? @pkg "^urllib$")
  (#match? @method "^(urlopen|urlretrieve|urlcleanup)$"))
