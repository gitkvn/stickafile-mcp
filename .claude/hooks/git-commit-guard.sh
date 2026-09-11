#!/usr/bin/env bash
# PreToolUse hook (matcher: Bash). Denies any Bash call that would create
# commits (git commit / cherry-pick / revert / rebase / am) unless the current
# branch is `dev`. `git merge` is deliberately NOT blocked.
#
# Reads the hook JSON on stdin, inspects .tool_input.command. Exit 0 with no
# output = no opinion (normal permission flow continues). A deny is returned
# as hookSpecificOutput.permissionDecision=deny with a reason.
set -u

REQUIRED_BRANCH="dev"
# git subcommands that write commits to the current branch (merge intentionally excluded)
COMMIT_WORDS='(commit|cherry-pick|revert|rebase|am)'

input=$(cat)
cmd=$(printf '%s' "$input" | jq -r '.tool_input.command // empty' 2>/dev/null)
[ -z "$cmd" ] && exit 0

# Word-boundary matchers (grep -E has no \b on macOS/BSD; emulate it).
W='(^|[^[:alnum:]_])'
E='([^[:alnum:]_]|$)'
has_word() { printf '%s' "$cmd" | grep -qE "${W}$1${E}"; }

project_dir="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"

# --- 1. Is this a commit-creating command? ---------------------------------
is_commit=0
if has_word 'git'; then
  if has_word "$COMMIT_WORDS"; then
    is_commit=1            # git commit, git -c x=y commit, cd .. && git commit, sh -c "git commit"
  else
    # git aliases: `git ci` where alias.ci expands to one of COMMIT_WORDS
    while IFS=' ' read -r name expansion; do
      [ -z "$name" ] && continue
      name=${name#alias.}
      if printf '%s' "$expansion" | grep -qE "${W}${COMMIT_WORDS}${E}" && has_word "$(printf '%s' "$name" | sed 's/[][\.*^$/]/\\&/g')"; then
        is_commit=1; break
      fi
    done < <(git -C "$project_dir" config --get-regexp '^alias\.' 2>/dev/null)
  fi
fi
[ "$is_commit" -eq 0 ] && exit 0

deny() {
  jq -cn --arg r "$1" '{
    systemMessage: ("git-commit-guard: " + $r),
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: $r
    }
  }'
  exit 0
}

# --- 2. Which repo(s) would the commit land in? --------------------------

# Redirecting git at another repo/worktree is never needed here; refuse outright.
if printf '%s' "$cmd" | grep -qE -- '--git-dir|--work-tree|GIT_DIR=|GIT_WORK_TREE='; then
  deny "command redirects git to another repo/worktree (--git-dir/--work-tree/GIT_DIR); commits must be made on branch '${REQUIRED_BRANCH}' in the main checkout. Stop and tell the user."
fi

dirs=("$project_dir")
# Every `cd X`, `pushd X`, or `git -C X` target is also checked. Paths that
# can't be resolved (quotes, variables, spaces) are refused rather than guessed.
while read -r target; do
  [ -z "$target" ] && continue
  target=$(printf '%s' "$target" | sed -E 's/^(cd|pushd|-C)[[:space:]]+//')
  # strip one layer of matching quotes; expand a leading $HOME / ${HOME} / ~
  case "$target" in
    \"*\") target=${target#\"}; target=${target%\"} ;;
    \'*\') target=${target#\'}; target=${target%\'} ;;
  esac
  case "$target" in
    '$HOME'/*)   target="${HOME}${target#\$HOME}" ;;
    '${HOME}'/*) target="${HOME}${target#\$\{HOME\}}" ;;
  esac
  case "$target" in
    ~*)  target="${HOME}${target#\~}" ;;
    /*)  ;;
    \$*|\"*|\'*|\`*) deny "cannot resolve directory target '$target' in command; refusing to guess which repo the commit lands in. Stop and tell the user." ;;
    *)   target="$project_dir/$target" ;;
  esac
  if [ ! -d "$target" ]; then
    deny "directory '$target' does not exist; cannot verify branch for commit. Stop and tell the user."
  fi
  dirs+=("$target")
done < <(printf '%s' "$cmd" | grep -oE "(^|[;&|[:space:]])(cd|pushd|-C)[[:space:]]+[^[:space:];&|]+" | sed -E 's/^[;&|[:space:]]+//')

# --- 3. Branch check in each candidate repo -------------------------------
for d in "${dirs[@]}"; do
  branch=$(git -C "$d" branch --show-current 2>/dev/null)
  if [ -z "$branch" ]; then
    if git -C "$d" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      deny "HEAD is detached in '$d' (no branch); commit-creating git commands (commit/cherry-pick/revert/rebase/am) are only allowed on branch '${REQUIRED_BRANCH}'. Stop and tell the user — do not switch branches."
    fi
    continue   # not a git repo; nothing to guard there
  fi
  if [ "$branch" != "$REQUIRED_BRANCH" ]; then
    deny "BLOCKED: commit-creating git commands (commit/cherry-pick/revert/rebase/am) are only allowed on branch '${REQUIRED_BRANCH}'. Current branch in '$d' is '$branch'. Stop and tell the user — do not switch branches, do not retry with a different phrasing."
  fi
done

exit 0
