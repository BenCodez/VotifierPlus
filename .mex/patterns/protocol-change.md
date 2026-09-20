---
name: protocol-change
description: Preserve explicit V1 compatibility and V2 authentication boundaries.
triggers: [protocol, V1, V2, token]
last_updated: 2026-09-20
mex:
  id: mx_01M307A5QQDBA5HQKJCQ24BVRX
  type: pattern
  status: promoted
  revision: 1
  title: protocol-change
---

# Protocol change

Trace handshake, prefix detection, framed/unframed parsing, V1 collision handling, signature verification, and event dispatch. Test TokenSupport and DisableV1 independently; V2 can be parsed when TokenSupport is false, while token support alone leaves V1 allowed under current defaults. Parsing/collision tests are in `VotifierPlus/src/test/java/com/bencodez/votifierplus/tests/VoteReceiverTest.java`; mode rejection tests are in `VotifierPlus/src/test/java/com/bencodez/votifierplus/tests/VoteProtocolSecurityTest.java`.
