---
name: network
description: Connection budget and proxy header trust boundary.
triggers: [network, PROXY, throttle, thread, tunnel]
last_updated: 2026-09-20
mex:
  id: mx_01M307CW4VKS6V9B37VZQDZN8F
  type: component
  status: promoted
  revision: 1
  title: Connection and proxy header boundary
---

# Connection boundary

The receiver uses bounded connection and forwarding executors and timeouts. Throttling is available but disabled in default configuration. The connection handler processes optional PROXY/CONNECT headers before vote parsing. Only textual PROXY v1 currently supplies a reported client IP for throttling; PROXY v2 is discarded and CONNECT does not supply one. There is no trusted-proxy allowlist for PROXY v1 in this path, so a directly connected client can spoof that metadata and affect attribution/throttle keys. It does not bypass V2 HMAC authentication. Source: `VotifierPlus/src/main/java/com/vexsoftware/votifier/net/VoteReceiver.java`, `VotifierPlus/src/main/java/com/vexsoftware/votifier/net/VoteConnectionHandler.java`, `VotifierPlus/src/main/java/com/vexsoftware/votifier/net/ProxyHeaderProcessor.java`, `VotifierPlus/src/main/resources/config.yml`.

Tunnel egress IP settings and per-client bans have different purposes: the documented throttle policy warns not to put ordinary backend/proxy IPs in the tunnel list, and per-client bans require a known real client IP. Check both parser tests and throttle tests when changing this boundary. Source: `VotifierPlus/src/main/resources/config.yml`, `VotifierPlus/src/test/java/com/bencodez/votifierplus/tests/VoteReceiverThrottleTest.java`.
