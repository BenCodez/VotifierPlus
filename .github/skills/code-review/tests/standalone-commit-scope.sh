#!/usr/bin/env bash
set -euo pipefail

skill_file="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/SKILL.md"

require_text() {
    local text="$1"
    if ! grep -Fq "$text" "$skill_file"; then
        printf 'missing required review guidance: %s\n' "$text" >&2
        exit 1
    fi
}

require_text 'git worktree add --detach'
require_text 'temporary checkout'
require_text 'currently checked-out worktree and its artifacts cannot provide evidence'
require_text 'git -C "$review_worktree" diff --check "$parent_sha" "$commit_sha"'
require_text 'perform separate, explicitly labeled'
require_text 'Do not substitute an unrelated current-checkout `git diff --check` or build'

printf 'standalone commit scope guidance: ok\n'
