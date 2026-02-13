#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./chutes_sync_upstream.sh [options]

Creates a new branch from upstream, applies the Chutes proxy patch, bumps the
workspace version, optionally tags, and pushes.

Options:
  --upstream-ref REF   Upstream ref to base on (default: upstream/main)
  --patch PATH         Patch file to apply (default: inferred from upstream SHA)
  --version X.Y.Z      Version to set in codex-rs/Cargo.toml (default: bump from latest chutes-v*)
  --no-tag             Do not create a chutes-vX.Y.Z tag
  --push               Push the branch (default)
  --no-push            Do not push anything
  --update-main        Push this branch to origin/main (fast-forward) to kick CI
  -h, --help           Show help

Examples:
  ./chutes_sync_upstream.sh --update-main
  ./chutes_sync_upstream.sh --version 0.0.2 --update-main
  ./chutes_sync_upstream.sh --patch patches/chutes-non-openai-responses-proxy-e00080cea.patch
EOF
}

repo_root() {
  git rev-parse --show-toplevel 2>/dev/null
}

infer_patch_file() {
  local short_sha="$1"
  local candidate="patches/chutes-non-openai-responses-proxy-${short_sha}.patch"
  if [[ -f "${candidate}" ]]; then
    echo "${candidate}"
    return 0
  fi

  if [[ -f "patches/chutes-non-openai-responses-proxy.patch" ]]; then
    echo "patches/chutes-non-openai-responses-proxy.patch"
    return 0
  fi

  return 1
}

next_version_from_tags() {
  python3 - <<'PY'
import re
import subprocess

out = subprocess.check_output(["git", "tag", "-l", "chutes-v*"], text=True).splitlines()
tags = []
for t in out:
    m = re.fullmatch(r"chutes-v(\d+)\.(\d+)\.(\d+)", t)
    if not m:
        continue
    tags.append((int(m.group(1)), int(m.group(2)), int(m.group(3))))

if not tags:
    print("0.0.1")
    raise SystemExit(0)

tags.sort()
maj, min_, patch = tags[-1]
patch += 1
print(f"{maj}.{min_}.{patch}")
PY
}

set_workspace_version() {
  local version="$1"

  python3 - <<PY
import pathlib
import re
import sys

path = pathlib.Path("codex-rs/Cargo.toml")
text = path.read_text(encoding="utf-8")

m = re.search(r"(?ms)^\\[workspace\\.package\\]\\s*\\n.*?^version\\s*=\\s*\"([^\"]+)\"", text)
if not m:
    raise SystemExit("Could not find [workspace.package] version in codex-rs/Cargo.toml")

old = m.group(1)
new = "${version}"

replacement = m.group(0).replace(f'version = \"{old}\"', f'version = \"{new}\"')
text2 = text[: m.start(0)] + replacement + text[m.end(0) :]
path.write_text(text2, encoding="utf-8")
print(f"Updated workspace version {old} -> {new}")
PY
}

main() {
  local upstream_ref="upstream/main"
  local patch_file=""
  local version=""
  local create_tag="true"
  local push="true"
  local update_main="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --upstream-ref)
        upstream_ref="$2"
        shift 2
        ;;
      --patch)
        patch_file="$2"
        shift 2
        ;;
      --version)
        version="$2"
        shift 2
        ;;
      --no-tag)
        create_tag="false"
        shift
        ;;
      --push)
        push="true"
        shift
        ;;
      --no-push)
        push="false"
        shift
        ;;
      --update-main)
        update_main="true"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "Unknown argument: $1" >&2
        usage >&2
        exit 2
        ;;
    esac
  done

  local root
  root="$(repo_root)"
  if [[ -z "${root}" ]]; then
    echo "Not in a git repo." >&2
    exit 1
  fi
  cd "${root}"

  if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "Working tree has tracked changes. Commit or stash before running." >&2
    exit 1
  fi

  git fetch upstream
  git fetch origin

  local upstream_sha short_sha branch backup_branch
  upstream_sha="$(git rev-parse "${upstream_ref}")"
  short_sha="$(git rev-parse --short=9 "${upstream_sha}")"
  branch="chutes-upstream-${short_sha}-proxy"

  backup_branch="backup/main-$(date +%Y%m%d-%H%M%S)-$(git rev-parse --short=9 origin/main)"
  if ! git show-ref --verify --quiet "refs/heads/${backup_branch}"; then
    git branch "${backup_branch}" origin/main
  fi

  if [[ -z "${patch_file}" ]]; then
    if ! patch_file="$(infer_patch_file "${short_sha}")"; then
      echo "Could not infer patch file for upstream SHA ${short_sha}." >&2
      echo "Pass --patch PATH (example: patches/chutes-non-openai-responses-proxy-${short_sha}.patch)." >&2
      exit 1
    fi
  fi

  if [[ ! -f "${patch_file}" ]]; then
    echo "Patch file not found: ${patch_file}" >&2
    exit 1
  fi

  git checkout -B "${branch}" "${upstream_sha}"

  git apply --index "${patch_file}"
  git commit -m "chutes: responses proxy compatibility (${short_sha})"

  if [[ -z "${version}" ]]; then
    version="$(next_version_from_tags)"
  fi
  if [[ ! "${version}" =~ ^[0-9]+\\.[0-9]+\\.[0-9]+$ ]]; then
    echo "Invalid --version '${version}'. Expected X.Y.Z" >&2
    exit 1
  fi

  set_workspace_version "${version}"
  git add codex-rs/Cargo.toml
  if ! git diff --cached --quiet; then
    git commit -m "chore(release): bump workspace version to ${version}"
  fi

  local tag_name="chutes-v${version}"
  if [[ "${create_tag}" == "true" ]]; then
    if git rev-parse "${tag_name}" >/dev/null 2>&1; then
      echo "Tag already exists: ${tag_name}" >&2
      exit 1
    fi
    git tag -a "${tag_name}" -m "${tag_name}"
  fi

  if [[ "${push}" == "true" ]]; then
    git push -u origin "${branch}"
    if [[ "${update_main}" == "true" ]]; then
      git push origin "${branch}:main"
    fi
    if [[ "${create_tag}" == "true" ]]; then
      git push origin "${tag_name}"
    fi
  fi

  echo "Created:"
  echo "  backup branch : ${backup_branch}"
  echo "  working branch: ${branch}"
  if [[ "${create_tag}" == "true" ]]; then
    echo "  tag           : ${tag_name}"
  fi
}

main "$@"

