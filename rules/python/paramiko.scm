; Detects SSH connections via paramiko — a strong signal that code can
; reach remote machines over SSH, which is a network_access + privilege pattern.
; Matches: paramiko.SSHClient(), paramiko.Transport(), paramiko.SFTPClient.from_transport()
(call
  function: (attribute
    object: (identifier) @pkg
    attribute: (identifier) @cls)
  (#match? @pkg "^paramiko$")
  (#match? @cls "^(SSHClient|Transport|SFTPClient|RSAKey|ECDSAKey|Ed25519Key|AutoAddPolicy|RejectPolicy)$"))
