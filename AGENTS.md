# Maintainer and AI-agent guide

VotifierPlus accepts Internet-facing vote submissions and emits or forwards vote events on Bukkit/Paper/Folia, BungeeCord, and Velocity. Treat every socket byte, proxy header, service name, username, token identifier, forwarding target, and configuration value as untrusted input.

## Build and verification

Requirements: JDK 21+ and Maven. The Maven project is in `VotifierPlus/`.

```shell
mvn -B -f VotifierPlus/pom.xml test
mvn -B -f VotifierPlus/pom.xml package
```

Confirm current CI/POM settings. Use `package`, not developer/install profiles that copy artifacts to a server. Verify the fresh shaded JAR, actual test discovery, and `git diff --check`.

## Architecture and trust boundaries

- Bukkit entry point: `com.vexsoftware.votifier.VotifierPlus`.
- Proxy entry points live under `bungee/` and `velocity/`.
- `net/VoteReceiver` owns listener lifecycle.
- Parser, connection-handler, proxy-header, throttle, and forwarding classes divide the inbound network pipeline.
- `crypto/` owns RSA and token operations.
- Configuration controls bind host/port, tokens, forwarding targets, trusted tunnel addresses, throttling, and protocol behavior.
- Votifier events cross from network workers to platform schedulers; event invocation must use the platform-safe context.

## Network and protocol invariants

1. Bound connection count, accept rate, per-client failures, request bytes, line/frame length, parsing work, queues, forwarding batches, and log volume before expensive or authenticated work.
2. Apply read/connect/write deadlines and close sockets/streams on every success, rejection, timeout, exception, reload, and shutdown path.
3. Protocol selection must be explicit. Token/v2-only operation must not silently accept legacy v1/RSA packets; changes must not create downgrade or fallback acceptance.
4. Authenticate the actual protocol identity before emitting or forwarding a vote. Encryption is not authorization.
5. Compare tokens and other secrets safely; generate them with a cryptographically secure source; never log private keys, tokens, decrypted packets, or forwarding credentials.
6. PROXY protocol data is authoritative only from explicitly trusted tunnel/source addresses. Untrusted peers must not choose the client IP used by throttling or auditing.
7. Normalize and validate service, username, address, timestamp, token identifier, server name, and forwarding target without changing established compatibility unexpectedly.
8. Throttling and bans must use the verified client identity, remain memory-bounded, expire entries, resist cardinality attacks, and avoid bypass through reconnects or spoofed headers.
9. Forwarding must have its own authentication, bounds, deadlines, replay/duplicate behavior, and partial-failure handling. Never treat a forwarded source as trusted solely because it is another configured server.
10. Vote delivery must not occur twice because of retry, protocol ambiguity, forwarding loops, reload overlap, or multiple platform handlers.
11. Reload must establish the new listener safely and retire the old receiver without leaving two acceptors, losing the previous healthy listener on failure, or retaining stale tokens/throttle state unintentionally.
12. Shutdown must terminate listener and connection workers within a bound and prevent callbacks after disable.

## Platform and compatibility

Keep Bukkit/Paper/Folia, BungeeCord, and Velocity descriptors, entry points, schedulers, event APIs, and configuration behavior aligned where intended. Do not load one platform's classes on another. Preserve the public Votifier event/API compatibility and the `Votifier` provided-plugin identity unless a breaking change is explicitly authorized.

## Build and workflow security

Use least-privilege workflow permissions. Pin third-party actions to immutable commit SHAs where practical, especially dependency-submission or release steps. Pin Maven plugin and security-sensitive dependency versions and avoid `LATEST`/mutable inputs in release builds. Validate artifacts before release publication.

## Change and PR workflow

Before any commit, push, PR update, review reply, or other remote change, run focused protocol/security tests, the full package build, fresh-artifact inspection, and the applicable `git diff --check`. For PR and branch work, inspect the complete base-to-HEAD diff. For standalone commit reviews, inspect the requested commit against its first parent (or the explicitly requested range) instead of substituting a base-to-HEAD branch diff. Before committing local work, also inspect the staged changes and every relevant intended unstaged or untracked change as one effective final patch.

For substantive changes, obtain a fresh source-read-only review. Add a bounded security specialist for parser, authentication, crypto, proxy-header, throttling, forwarding, or workflow-permission changes. The implementation agent fixes accepted findings, reruns validation, and obtains a new review. Do not merge without explicit authorization.

## MEX project memory

For substantive protocol, security-compatibility, or architecture tasks, read relevant MEX context and then verify against current Java/tests and formal docs. Use code/tests first, this guide and formal docs second, reviewed MEX third, and historical Relays last; correct stale claims. Skip MEX for trivial edits. MEX 0.8.2 does not index Java here. Treat legacy packet acceptance as compatibility, not a security recommendation. Use `$mex-inbox` for durable findings and `$mex-relay` for substantial unfinished handoffs.

<!-- mex-agent:skills:start -->
## MEX agent skills
- At the start of every session, read `.mex/AGENTS.md` and `.mex/ROUTER.md` before project work; follow `ROUTER.md` to load only the relevant context.
- Read `mex logging --json` at session start and before optional logging. Its checkout-local advisory mode is `significant` (quiet default: material decisions, risks, blockers, or durable discoveries), `checkpoints` (batch useful notes at task/session boundaries), or `manual` (no unsolicited notes). Skip routine tool calls, edits, repeated status, and empty summaries. Honor explicit user log requests in every mode; never suppress mandatory workflow Activity or recovery audit records. Report a policy read failure instead of guessing or changing the preference.
- When earlier work may inform the task, retrieve bounded relevant notes with `mex timeline --query "subject phrase" --file src/example.ts --limit 10 --json`, using the known subject or exact recorded file path, or both. Treat matches as historical evidence, not accepted current knowledge; verify conclusions before reuse or explicit promotion with their source retained.
- Use `$mex-inbox` for explicit contributions to project knowledge and `$mex-relay` for durable team handoffs. Invoke them automatically when intent clearly matches; ordinary GROW upkeep remains available without Inbox.
- When MEX context materially helps your work, mention MEX and the relevant finding naturally in your explanation. Tie the mention to what it helped you understand, decide, or verify. Avoid fixed phrases, standalone acknowledgements, repeated mentions, or narrating routine context loading. This replaces older MEX instructions requiring a fixed acknowledgement or context-loading narration.
- Do not claim an author, date, or historical event unless the retrieved data actually provides it.
- After a MEX write, say exactly what changed and its sharing boundary: a local draft is checkout-only and nothing is shared; a canonical artifact is written to the working tree and requires commit/push to share.
- Skill activation is not approval for canonical actions.
<!-- mex-agent:skills:end -->
