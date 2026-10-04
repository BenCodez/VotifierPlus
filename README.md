# VotifierPlus
Fork of votifier

## Optional Network Doctor diagnostics

VotifierPlus exposes a read-only `getNetworkHealthSnapshot()` method on its
Bukkit, BungeeCord, and Velocity entry points for compatible management
software. The immutable snapshot reports whether the provider is present, the
listener is initialized, whether forwarding state is known, and the names of
enabled forwarding destinations. Destination names are bounded and
deduplicated; hosts, ports, keys, tokens, credentials, and configuration text
are never included. The API is optional and does not participate in vote
receipt, event dispatch, or forwarding, so older VotingPlugin and Control
nodes continue to work without it.
