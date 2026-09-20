---
name: architecture
description: Vote receiver and platform event boundary.
triggers: [architecture, vote, event, proxy]
last_updated: 2026-09-20
mex:
  id: mx_01M307A5P51CDX3XQVFMYGA7BA
  type: architecture
  status: promoted
  revision: 1
  title: architecture
---

# Vote delivery boundary

The network receiver parses an accepted socket into a vote request, and platform adapters expose Votifier events for Bukkit, BungeeCord, or Velocity consumers. VotingPlugin consumes the Votifier API event but owns downstream totals/rewards; this repository does not prove vote reward durability. Source: `VotifierPlus/src/main/java/com/vexsoftware/votifier/net/VoteReceiver.java`, `VotifierPlus/src/main/java/com/vexsoftware/votifier/model/VotifierEvent.java`, `VotifierPlus/src/main/java/com/vexsoftware/votifier/bungee/`, `VotifierPlus/src/main/java/com/vexsoftware/votifier/velocity/`.

Forwarding is a separate outbound path configured per target server. Keep receive authentication and forwarding credentials distinct. Source: `VotifierPlus/src/main/java/com/vexsoftware/votifier/net/VoteForwarder.java`, `VotifierPlus/src/main/resources/config.yml`.
