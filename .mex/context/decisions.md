---
name: decisions
description: Current, legacy, and security categories.
triggers: [decision, security, downgrade, legacy]
last_updated: 2026-09-20
mex:
  id: mx_01M307CFHKV470P8EA8CZ8QVQN
  type: decision
  status: promoted
  revision: 1
  title: Security and compatibility categories
---

# Security and compatibility categories

Current required behavior: reject malformed or unauthenticated V2 votes and honor `DisableV1` when set. Legacy compatibility behavior: defaults currently leave V1 enabled, and the receiver warns when TokenSupport is on without DisableV1. That compatibility default is not a recommendation for token-only deployments. Known security concern: enabling tokens alone still permits V1 acceptance, so a site requiring token-authenticated votes must disable V1 only after confirming every configured sender supports V2. Source: `VotifierPlus/src/main/resources/config.yml`, `VotifierPlus/src/main/java/com/vexsoftware/votifier/net/VoteReceiver.java`, `VotifierPlus/src/test/java/com/bencodez/votifierplus/tests/VoteProtocolSecurityTest.java`.

Future desired behavior is not specified by this checkout. Do not silently reinterpret the compatibility default as a promised migration plan.
