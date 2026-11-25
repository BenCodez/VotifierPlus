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

Eligible transport failures before a payload write can be retried. The first
retry always waits 60 seconds after the original failure. Later retries wait
`ForwardingRetry.RetryIntervalSeconds` seconds after the preceding failure
(default 300, valid range 1–3600). `ForwardingRetry.MaxRetries` counts retries
after the initial send (default 12, valid range 0–3600). Zero disables retrying.
Missing or invalid settings use their defaults. No retry begins at or after
one hour from the original failure, even when the configured count would
allow more attempts. With the defaults, up to 12 retries fit within that hour.

Each destination can override those three settings under
`Forwarding.<destination>.ForwardingRetry`. Missing or invalid overrides inherit
the validated global values. Explicit `false` turns off the success gate and
explicit `0` for `MaxRetries` disables retries for that destination. The
60-second first delay and one-hour cutoff apply to every destination.

`ForwardingRetry.RequirePreviousSuccessBeforeRetry` defaults to `true`. Each
destination must first complete a normal vote payload write and flush on its
current configuration. A connection or handshake alone does not qualify.
Forwarding has no receiver acknowledgement, so transport success does not
confirm authentication or processing at the destination. New incoming votes
are still forwarded normally. Failures before the first transport success are
discarded and are never replayed. Set this option to `false` to retry eligible
failures before the first transport success.

The receiver keeps up to 256 pending vote–destination pairs in RAM. New
failures are dropped from the retry queue when full. A change to the target
host, port, protocol, credential, or effective retry settings invalidates cached success for that
destination and pending retries for the previous identity. Disabled or removed
targets cannot retry. Reload and shutdown clear pending retries and prior
successes. Protocol or payload errors and failures after writing begins are
terminal because the receiver may already have accepted the vote.
