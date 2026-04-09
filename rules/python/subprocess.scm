; Detects shell/subprocess execution via the subprocess module and os.system.
; These are high-signal privilege patterns — code gaining ability to run
; arbitrary system commands.
; Matches: subprocess.run(), subprocess.call(), subprocess.Popen(),
;          subprocess.check_output(), subprocess.check_call(),
;          os.system(), os.popen()
(call
  function: (attribute
    object: (identifier) @pkg
    attribute: (identifier) @method)
  (#match? @pkg "^subprocess$")
  (#match? @method "^(run|call|Popen|check_output|check_call|getoutput|getstatusoutput|communicate)$"))

; os.system("cmd") and os.popen("cmd")
(call
  function: (attribute
    object: (identifier) @pkg
    attribute: (identifier) @method)
  (#match? @pkg "^os$")
  (#match? @method "^(system|popen)$"))
