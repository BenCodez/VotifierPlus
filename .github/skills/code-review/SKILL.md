---
name: code-review
description: >-
  Review VotifierPlus pull requests, branch diffs, commits, and explicitly
  included local changes before publishing. Use for code review, pre-PR review,
  regression review, security review, and PR readiness. Perform an independent
  source-read-only review and report only concrete P0-P3 defects with precise
  file/line locations. Do not use this skill to implement fixes.
---

# VotifierPlus code review

Review the exact proposed change and follow applicable `AGENTS.md`. Treat the Internet-facing listener, protocol parsers, authentication, forwarding, proxy-header handling, throttling, and platform event handoff as high-risk boundaries.

## Boundaries and scope

Do not edit, fix, commit, push, approve, merge, change PR state, or independently post comments. Preserve unrelated work; never stash, reset, clean, rebase, or switch branches. Run only safe bounded local checks; do not bind public ports, contact production servers, use real credentials, or weaken validation.

Resolve the actual PR base/SHA, merge base, review HEAD SHA, commit list, complete patch, changed paths, and worktree state. Review every commit and file in the merge-base-to-HEAD range. Disclose local overlays, untracked/generated/binary content, missing history, multiple merge bases, conflicts, or truncation. When the task explicitly includes local work, review the applicable staged, unstaged, and intended untracked content as overlays on the pinned commit and assess the effective final code; disclosure alone is not coverage. Pin and recheck the snapshot.

Use a fresh reviewer for substantive changes when supported. Add a bounded security specialist for changes to parsing, authentication, cryptography, PROXY protocol, throttling, forwarding, or workflow privileges.

## VotifierPlus review lenses

Trace attacker-controlled bytes from accept through source identification, protocol selection, size/framing checks, authentication/decryption, semantic validation, throttling, vote construction, forwarding, scheduler handoff, event emission, logging, reload, and shutdown.

- Check connection/admission limits, read/connect/write deadlines, bounded frames/lines/bodies, slow clients, partial reads, malformed encodings, oversized values, EOF, and closure of every socket/stream.
- Verify v1 RSA versus v2 token selection. Token-only configuration must not accept legacy packets through fallback, ambiguous framing, exception recovery, or forwarding.
- Verify token/key generation, storage, comparison, rotation/reload, permissions, error messages, and redaction. Encryption alone does not authenticate the claimed service or server.
- Accept PROXY protocol identity only from configured trusted peers. Ensure throttling, bans, logs, and authorization use the verified source rather than an attacker-supplied address.
- Test throttle cardinality bounds, expiration, concurrency, tunnel-specific rules, ban escalation, reconnect bypass, log suppression, and cleanup.
- Validate service names, usernames, addresses, timestamps, token identifiers, server names, and forwarding targets before allocation, logging, event emission, or connection.
- Check replay, duplicate delivery, forwarding loops, partial multi-target failure, retry behavior, and mixed v1/v2 peers against the documented delivery contract.
- Verify Bukkit/Folia/BungeeCord/Velocity thread ownership, optional class loading, descriptors, provided Votifier API compatibility, and callbacks after disable.
- Review reload/listener replacement for duplicate acceptors, port leaks, loss of a previously healthy receiver, stale tokens, and races with active connections.
- Check workflow least privilege, immutable action pins, dependency/plugin pins, artifact validation, and safe release ordering when CI changes.
- Missing tests alone are not a finding; demonstrate broken behavior or a defective test contract. Use synthetic packets and credentials, never production data.

## Validation

Confirm current CI/POM requirements. At the time this skill was added:

```shell
mvn -B -f VotifierPlus/pom.xml package
```

Record working directory, command, snapshot, exit result, discovered tests, and fresh artifact. Run `git diff --check`. Do not count skipped/zero tests, stale artifacts, or another snapshot as proof. Distinguish introduced failures, reproduced baseline failures, and environmental blockers.

## Findings and result

For every candidate, prove a reachable trigger, responsible changed lines, missing guard, expected behavior, and impact. Drop speculation, style preferences, unrelated old defects, and findings contradicted by final code. Use the lowest accurate priority:

- P0: immediately critical, broadly exploitable release blocker.
- P1: authentication bypass, common remote failure, serious exposure, outage, corruption, deadlock, or major compatibility break.
- P2: concrete bounded or edge-case correctness, reliability, resource, or security defect.
- P3: low-impact concrete defect.

Anchor findings to the smallest useful changed-line range and explain trigger, mechanism, and consequence.

Determine completeness separately from findings: report findings when complete; use exactly `No findings.` when complete and clean; use `Review incomplete.` only when required coverage or validation is missing, unresolved, or stale. A static-only review does not satisfy a required build/security gate.

The implementation coordinator fixes accepted findings, reruns validation, and obtains a fresh review. This reviewer never publishes or merges.
