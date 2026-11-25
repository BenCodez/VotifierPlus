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

## Forwarding retries

When a forwarding connection fails before the vote payload starts writing,
VotifierPlus retries that destination after 15 minutes. It uses 15-minute
delays for the first five retries, then 30-minute delays while the destination
remains eligible. Other destinations continue independently. Protocol or
payload preparation errors are terminal. Once a payload write begins, the
receiver may have accepted the vote, so VotifierPlus does not retry an error
from that point.

The receiver keeps up to 256 pending vote/destination pairs in memory. If the
queue fills, new failures are dropped from the retry queue. Pending retries
are discarded when the receiver reloads or shuts down. No retry state survives
a restart. Each retry checks the destination and uses its current credentials
for the same forwarding protocol.
