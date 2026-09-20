---
name: protocol
description: Current V1/V2 parsing and token compatibility.
triggers: [protocol, token, RSA, V1, V2]
last_updated: 2026-09-20
mex:
  id: mx_01M307CW4VM5CZ0SZXZBWYWHK7
  type: constraint
  status: promoted
  revision: 1
  title: Vote protocol versions
---

# Protocol versions

Current behavior: V2 votes use a token/HMAC-SHA256 signature; the parser accepts framed and unframed V2 forms and checks the challenge. V2 parsing is not gated by `TokenSupport`; that setting affects handshake selection and the compatibility warning. `DisableV1` rejects legacy V1 packets and forces a V2 handshake. Token support alone does not disable V1. Source: `VotifierPlus/src/main/java/com/vexsoftware/votifier/net/VoteParser.java`, `VotifierPlus/src/main/java/com/vexsoftware/votifier/net/VoteConnectionHandler.java`, `VotifierPlus/src/test/java/com/bencodez/votifierplus/tests/VoteProtocolSecurityTest.java`, `VotifierPlus/src/test/java/com/bencodez/votifierplus/tests/VoteReceiverTest.java`.

Legacy compatibility: V1 uses a fixed 256-byte RSA packet. A V1 block may begin with bytes that look like a V2 frame; the parser has a bounded collision/grace path rather than treating the prefix alone as definitive. Disabling V1 is a deployment compatibility choice for sites that still send V1. Source: `VotifierPlus/src/main/java/com/vexsoftware/votifier/net/VoteParser.java`, `VotifierPlus/src/main/java/com/vexsoftware/votifier/net/VoteConnectionHandler.java`, `VotifierPlus/src/test/java/com/bencodez/votifierplus/tests/VoteReceiverTest.java`, `VotifierPlus/src/main/resources/config.yml`.
