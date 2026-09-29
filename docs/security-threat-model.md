# VotifierPlus security threat model

This document defines the repository-specific threat model for code review and Codex Security scans. Read it with current source, tests, and `AGENTS.md`. Current code wins over old findings or historical descriptions.

VotifierPlus is unusual among the related projects because its main production interface is an intentionally Internet-reachable TCP listener. Security review should therefore prioritize remote protocol/authentication/resource failures over generic plugin correctness.

## Security objectives

VotifierPlus runs on Bukkit/Spigot/Paper/Folia, BungeeCord, and Velocity. It accepts Votifier v1/v2 packets, emits platform events, and can forward accepted votes.

The highest-value properties are:

1. authenticated protocols must only accept senders authorized under the configured protocol policy. Legacy V1 is the explicit compatibility exception: when `DisableV1=false`, possession of the normally distributed public key is sufficient to construct an accepted V1 packet, so V1 acceptance does not provide or promise sender authorization;
2. `DisableV1=true` must actually enforce v2-only/token-authenticated operation without fallback;
3. authenticated V2 votes and forwarded votes must not be replayed, duplicated, looped, or delivered more times than their intended contract permits. Legacy V1 has no nonce, challenge, or replay cache, so replay of an otherwise valid V1 packet while `DisableV1=false` is an intentional limitation of the supported legacy protocol rather than a blanket replay-prevention guarantee;
4. attacker-controlled vote fields must remain data and not become commands, SQL, paths, placeholders, log control sequences, or downstream syntax;
5. untrusted socket traffic must not exhaust workers, queues, memory, CPU, logs, or the Minecraft/proxy runtime;
6. PROXY metadata must affect client identity only when supplied by an explicitly trusted direct peer;
7. reload/shutdown must not create overlapping listeners, stale protocol policy, duplicate event delivery, or callbacks after disable;
8. forwarding must preserve the security semantics of the **configured target mode** and failure isolation. A target with a configured token should use the authenticated V2/challenge path without unintended downgrade; a target intentionally configured without a token uses legacy RSA/V1 forwarding by design and is not required to inherit V2 authentication from the ingress vote.

## Trust boundaries

### Remote attacker-controlled

Treat every TCP connection and its timing/fragmentation as hostile. This includes protocol prefixes, V1 ciphertext, V2 JSON, payload, signature, challenge response, service name, username, address, timestamp, packet length, concatenated packets, partial packets, disconnect timing, PROXY/CONNECT bytes, and direct peer address. A party that merely has the normally distributed V1 public key and can construct an accepted legacy V1 packet remains in this unauthenticated remote-attacker boundary; V1 encryption does not authenticate the sender.

PROXY-reported source addresses are authoritative only after the **direct socket peer** is validated against `TrustedProxyIps`.

### V2-authenticated but still untrusted

A real V2 voting service or other holder of a valid shared token may submit HMAC-authenticated traffic. That authentication proves possession of the selected V2 token and challenge response; it does not make service names, usernames, addresses, timestamps, or other payload fields safe for downstream interpreters.

Legacy V1 acceptance is **not** sender authentication and stays in the remote-attacker boundary above. A compromised V2 token holder can also send many separately valid votes unless a higher layer implements semantic duplicate/freshness policy.

### Trusted operator input

Listener bind/port, tokens, RSA key files, `TokenSupport`, `DisableV1`, trusted proxy addresses, forwarding destinations/credentials, throttling, and debug settings are operator-controlled. Misconfiguration is not a vulnerability unless lower-trust data can change it or code silently violates the configured security mode.

### Downstream consumers

Other plugins receiving Votifier events run in the same JVM and are not security-isolated. A malicious installed plugin already has broad power. However, public event/API boundaries still matter because benign downstream plugins may pass vote data into rewards, SQL, commands, or placeholders.

## Current security controls to preserve

Current master already includes important hardening. Security scans should test these for bypass/regression instead of repeatedly reporting their prior absence:

- `DisableV1` rejects legacy V1 and forces v2-only policy when selected;
- enabling `TokenSupport` without `DisableV1` emits a warning because V1 compatibility remains intentionally enabled;
- V2 uses HMAC-SHA256 and per-connection challenges;
- V2 packet reads have an absolute deadline and explicit packet-size bound;
- V1 reads a fixed 256-byte RSA block;
- protocol detection has a bounded V1/V2 collision/grace path for legacy compatibility;
- connection work uses a fixed pool with a bounded queue and stale-queue deadline;
- forwarding uses a bounded executor queue;
- sockets have read timeouts and bounded shutdown;
- PROXY v1 and CONNECT line sizes are bounded;
- PROXY source identity is accepted only from configured trusted direct peers;
- logging uses safety helpers for attacker-controlled fields/exceptions;
- regression tests cover v1 policy, parser behavior, trusted proxy handling, logging safety, and listener bounds.

A finding is most valuable when it demonstrates a way around one of these controls or a cross-feature interaction the control does not cover.

## V1 protocol and downgrade boundary

Votifier V1 is legacy RSA encryption and does not provide the same sender-authentication semantics as V2 token/HMAC. The public key is normally distributed to voting sites.

Legacy V1 compatibility is intentional when `DisableV1=false`. V1 has no per-vote challenge, nonce, or replay cache, so replaying the same correctly encrypted V1 packet is inherent to that legacy protocol. Do not report the default compatibility choice or that inherent V1 replay property alone as a vulnerability. Replay becomes security-relevant when code violates an explicitly stronger contract, such as accepting V1 while `DisableV1=true`, replaying authenticated V2/forwarded traffic beyond its intended semantics, or introducing an attacker-controlled amplification beyond one legacy packet replay.

High-value questions are:

- can V1 still be accepted anywhere when `DisableV1=true`?
- can a packet beginning like one protocol be reinterpreted as the other after an authentication/parsing failure?
- can framed/unframed V2 parse failure fall back to V1 in v2-only mode?
- can fragmentation, collision handling, or handshake timing bypass `DisableV1`?
- can reload briefly restore legacy acceptance after v2-only was configured?
- can forwarding downgrade an accepted V2 vote to a weaker form without an explicit trusted configuration decision?

Any **unintended inbound** V2-to-V1 downgrade or V1 acceptance by the receiving listener is especially important when the deployment explicitly selected `DisableV1=true`. Do not apply this warning to an operator-configured forwarding target that intentionally omits a token and therefore uses legacy V1 by design.

## V2 authentication and parsing

V2 authentication should bind the exact payload, correct token, and connection challenge before event delivery or forwarding.

Search for:

- HMAC computed over a normalized/reconstructed form instead of exact authenticated bytes;
- Base64, Unicode, duplicate JSON key, escaping, numeric/string coercion, or parser differentials between verification and semantic use;
- challenge confusion across connections;
- challenge reuse after failure;
- accepting missing/empty required fields;
- service-name token lookup ambiguity;
- `default` token behavior letting a token intended for one trust domain authenticate unexpected services;
- token identifiers, service-name casing, whitespace, Unicode, or normalization causing a different key to be selected than intended;
- trailing/concatenated data being ignored after one valid object;
- framed length mismatch, integer boundary, or unframed JSON-boundary confusion;
- packet-size enforcement after large allocation rather than before it;
- authentication or expensive JSON parsing occurring after attacker-controlled work that should have been bounded first.

Do not treat every malformed packet that is cleanly rejected as a security issue.

## PROXY and CONNECT handling

Only an explicitly trusted direct socket peer may supply authoritative PROXY metadata.

Search for:

- textual IP aliases, IPv4/IPv6 normalization, mapped addresses, hostnames, or zone identifiers bypassing the trusted-peer comparison;
- CONNECT or another tunnel mode modifying the effective source identity without the same trust check;
- a trusted proxy forwarding attacker-chosen nested PROXY/CONNECT headers that are parsed twice;
- protocol headers consumed inconsistently between detection, logging, throttling, and parsing;
- header length enforcement off by one, after allocation, or bypassed by missing terminators/fragmentation;
- spoofed effective addresses evading throttle buckets or poisoning audit data.

A recognizable PROXY v1/v2 header from an untrusted direct peer must fail closed: the connection is rejected and no vote is produced. Continuing after consuming such a header, even while falling back to the socket address, weakens the established boundary and should be treated as a regression.

## Resource exhaustion and abuse control

The listener is Internet-facing, so resource findings can be security-relevant even without authentication bypass.

Trace the complete admission path:

accept -> socket options -> connection queue -> queue age -> proxy-header parsing -> protocol detection -> packet read -> RSA/HMAC/JSON -> event scheduling -> forwarding queue -> outbound connection.

Look for:

- accepted sockets consuming resources before queue admission;
- queue rejection/timeout paths failing to close sockets;
- slow clients monopolizing all workers despite absolute deadlines;
- cryptographic CPU amplification, especially repeated V1 RSA decrypt attempts;
- large V2 allocation before the packet cap;
- cardinality attacks against throttle/log-suppression maps;
- attacker-controlled effective IPs creating unbounded throttle state;
- `CallerRunsPolicy` or equivalent forwarding saturation causing connection workers to perform outbound work and stall ingress;
- forwarding fan-out multiplying one accepted vote into excessive connection work;
- error paths generating one or more log lines per packet despite suppression;
- shutdown/reload waiting indefinitely on attacker-held sockets/tasks.

Require a credible traffic level and concrete resource impact when assigning severity.

## Vote field validation and downstream safety

Accepted vote fields remain lower-trust data.

Review username, service name, address, timestamp, and any future identifiers for:

- control/newline/terminal injection in logs;
- unsafe forwarding serialization;
- delimiter/framing injection into V1 or V2 forwarding;
- values that can alter token selection or forwarding routing;
- unexpected Unicode/null characters passed to downstream plugins;
- second-pass placeholder or command interpretation in code added here.

VotifierPlus does not need to solve every downstream plugin's command/SQL safety, but it should not introduce avoidable ambiguity or claim fields are trusted merely because the vote authenticated.

## Forwarding

Forwarding destinations are operator-controlled, so arbitrary configured destinations are normally not SSRF.

Security review should instead test:

- forwarding authentication and protocol negotiation according to the target's explicit configuration;
- whether V2 forwarding validates/uses the backend challenge correctly;
- accidental downgrade from authenticated ingress to a weaker egress mode when the target was configured/token-capable for V2;
- replay/duplicate forwarding on retry;
- forwarding loops;
- one backend's key/token being used for another destination;
- partial fan-out failures followed by duplication of successful targets;
- bounded connect/read/write deadlines;
- queue saturation changing event or connection-thread behavior;
- sensitive forwarding credentials in logs/errors.

A forwarded source should not be trusted merely because it is another configured Minecraft server. Likewise, do not classify an operator's explicit choice of a tokenless/V1 forwarding target as an authentication bypass by itself; report an unintended downgrade, wrong-target credential use, or behavior that violates the target's configured protocol mode.

## Event delivery, threading and lifecycle

Accepted network input crosses into Bukkit/Bungee/Velocity event systems.

Search for:

- Bukkit/Folia API use on arbitrary connection threads;
- the same vote emitted twice by parallel platform/forwarding paths;
- event dispatch after plugin disable;
- reload establishing a new receiver before the old listener/workers are retired;
- failed reload closing the last healthy listener;
- stale token/trusted-proxy/throttle policy remaining attached to an old runtime;
- in-flight forwarding from an old runtime duplicating a new runtime's forwarding;
- shutdown/reload losing accepted votes after an event has already been promised.

## Secrets and logging

Tokens, forwarding credentials, reusable authentication secrets, and decrypted authenticated payloads must not be exposed to remote clients or routine logs. V1 RSA private-key material is still sensitive, but its impact is primarily confidentiality of captured legacy V1 traffic rather than sender authentication: the corresponding public key is normally distributed and V1 acceptance does not authenticate the sender.

Search debug/error paths for:

- raw payloads;
- signatures/tokens;
- key material;
- full forwarding configuration;
- exception messages containing secrets;
- attacker-controlled terminal/control characters;
- high-volume logging before suppression.

Public RSA keys are not secrets.

## Build and supply chain

CI/release findings are relevant when untrusted PR-controlled code receives write-capable credentials, can poison artifacts/caches later consumed by trusted releases, or can modify published releases.

Do not inflate ordinary dependency hygiene into runtime critical severity. Keep mutable development dependencies, third-party action pinning, and least-privilege workflow issues calibrated to the actual token/release path.

## High-value attack stories

1. With `DisableV1=true`, send every ambiguous V1/V2 prefix and fragmentation pattern and try to obtain an accepted V1 vote.
2. Saturate the connection queue, then vary slow-read timing to see whether workers/sockets outlive the queue deadline.
3. Saturate the forwarding queue and observe whether `CallerRunsPolicy` turns connection workers into outbound forwarders.
4. From an untrusted direct IP, send PROXY/CONNECT variants and try to change the identity used by throttling.
5. From a trusted proxy, send malformed/nested proxy metadata and test single-vs-double parsing.
6. Authenticate V2 with service-specific/default token edge cases involving case, Unicode, whitespace, and duplicate JSON keys.
7. Send framed and unframed V2 with trailing/concatenated objects and verify exactly one authenticated request is consumed.
8. Reload while connections are queued, events are dispatching, and forwarding tasks are pending.
9. Forward one accepted vote to multiple targets, force partial failure, and verify successful targets are not duplicated.
10. Drive high-cardinality source identities/failures and verify throttle/log-suppression state remains bounded.

## Scan calibration and severity

**Critical:** remotely reachable unauthenticated vote creation in a deployment that **relies on V2/token authentication for the accepted vote path**, including any bypass that accepts a legacy V1 vote while `DisableV1=true`; HMAC or challenge verification bypass **when that bypass newly defeats a required V2 authentication boundary**; a key-selection flaw that lets an attacker create a V2 vote without possessing any token authorized for the accepted service/trust domain; remote arbitrary server/JVM code execution; remote leakage of V2/shared authentication tokens or other secrets that directly enable authenticated vote forgery.

When `DisableV1=false`, an unauthenticated remote client already has the intentionally supported legacy V1 submission path. In that mixed mode, an HMAC/challenge defect is not automatically Critical merely because V2 verification can be bypassed; classify it by the additional boundary or impact it creates beyond the already-permitted V1 semantics, such as bypassing a V2-only forwarding target, expanding service/token authority, or causing another concrete High/Critical effect.

Disclosure of only the receiver's legacy V1 private RSA key is **not automatically Critical** because it does not newly grant vote-submission capability; the public key is already distributed and V1 does not authenticate senders. Classify V1 private-key disclosure by the actual additional boundary crossed, such as exposure of captured vote contents, correlated sensitive metadata, or another concrete confidentiality/integrity impact.

**High:** practical replay/duplicate forwarding causing repeat rewards at scale; moderate-traffic worker/queue/memory exhaustion; trusted-proxy bypass enabling effective throttle evasion; forwarding authentication bugs that inject unauthenticated backend votes; protocol/downgrade confusion only when it produces a comparably high-impact integrity or availability consequence without meeting the Critical unauthenticated-vote condition.

**Medium:** downstream-dangerous field ambiguity with a realistic common sink; default-token or cross-service key-selection confusion where the attacker already possesses a valid token but can apply it beyond its intended service scope, without obtaining unauthenticated vote creation; parser fragmentation, downgrade, or protocol confusion that causes vote loss, rejection, or operational inconsistency **without** an authentication bypass or other High-impact consequence; reload races causing duplicate/missed votes; secret exposure to limited operators/log readers.

**Low:** admin-only footguns, malformed trusted config, build hardening without privileged-token exposure, cosmetic logging issues, or API misuse requiring a fully malicious installed plugin.

Do not report browser CSRF/session/DOM XSS classes unless a real browser surface is introduced. For every finding identify the attacker capability, configured protocol mode, exact trust boundary crossed, and concrete effect.
