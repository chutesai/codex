# Chutes Fork Patches

This fork tracks `upstream/main` closely, with a small set of Chutes-specific diffs.

## Responses Proxy Patch

`chutes-non-openai-responses-proxy-*.patch` contains the minimal Rust changes needed to
support tool calling against the Chutes Responses proxy (`https://responses.chutes.ai/v1`)
when using non-OpenAI models.

The patch files are plain diffs intended to be applied with `git apply`.

## Typical Upstream Sync Workflow

1. Fetch latest refs:

```bash
git fetch upstream
git fetch origin
```

2. Back up the current fork state:

```bash
git branch "backup/main-$(date +%Y%m%d-%H%M%S)-$(git rev-parse --short=9 origin/main)" origin/main
```

3. Create a new working branch from upstream:

```bash
up_sha="$(git rev-parse --short=9 upstream/main)"
git checkout -b "chutes-upstream-${up_sha}-proxy" upstream/main
```

4. Apply the patch:

```bash
git apply --index "patches/chutes-non-openai-responses-proxy-${up_sha}.patch"
git commit -m "chutes: responses proxy compatibility (${up_sha})"
```

If the patch doesn't apply cleanly, resolve conflicts manually, then regenerate the patch:

```bash
git diff upstream/main > "patches/chutes-non-openai-responses-proxy-${up_sha}.patch"
```

5. Bump the Rust workspace version (so `codex --version` is correct for release assets):

Edit `codex-rs/Cargo.toml` `[workspace.package] version`, then commit.

6. Run local checks (recommended):

```bash
cd codex-rs
just fmt
cargo test -p codex-core --all-features
```

7. Push and tag:

```bash
git push -u origin "chutes-upstream-${up_sha}-proxy"

# Optional: fast-forward origin/main to kick CI for nightly assets
git push origin "chutes-upstream-${up_sha}-proxy:main"

# Optional: create a versioned release tag
git tag -a "chutes-vX.Y.Z" -m "chutes-vX.Y.Z"
git push origin "chutes-vX.Y.Z"
```

## Automation Script

From repo root, `./chutes_sync_upstream.sh` automates the steps above.

Example:

```bash
./chutes_sync_upstream.sh --update-main
```

