---
name: proxy-connection-change
description: Keep proxy header, timeout, and throttle semantics distinct.
triggers: [PROXY, CONNECT, tunnel, throttle]
last_updated: 2026-09-20
mex:
  id: mx_01M307A5R34GQ529RP0RK12MQH
  type: pattern
  status: promoted
  revision: 1
  title: proxy-connection-change
---

# Proxy connection change

Trace socket peer, optional reported source IP, header bounds, parser deadline, and throttle key together. Reported source IP is not a vote credential. Check malformed/truncated headers and tunnel-mode behavior against `VotifierPlus/src/test/java/com/bencodez/votifierplus/tests/ProxyHeaderProcessorSecurityTest.java` and `VotifierPlus/src/test/java/com/bencodez/votifierplus/tests/VoteReceiverThrottleTest.java`.
