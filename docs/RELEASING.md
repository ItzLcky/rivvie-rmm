# Releasing

A release is a git tag. Nothing in the source needs to change for agents or the image to get the
right version: the [image workflow](../.github/workflows/image.yml) reads it from the tag.

| Build | Agent version | Image tags |
|---|---|---|
| Tag `v0.2.0` | `0.2.0` | `0.2.0`, `sha-…` |
| Push to `main` | next patch after the newest tag, as a pre-release numbered by the run: `0.2.1-dev.57` | `latest`, `sha-…` |

Every build is newer than the one before it, so agents with automatic updates move to it, and a
later `v0.2.1` sorts above all `0.2.1-dev.N` builds. The crate versions in `Cargo.toml` are only
the fallback when a repository has no tags, and what a local build reports.

## One-time setup

1. **Release key.** `cargo run -p rmm-sign -- keygen --out release.key` prints
   `RMM_UPDATE_PUBKEY=<hex>`. Keep `release.key` and a backup of it **offline**: it signs every
   agent update and all detection content, and a lost key means every deployed agent has to be
   reinstalled (the public half is compiled into them). It must never be on the server.
2. **Repository settings** (GitHub → Settings → Secrets and variables → Actions): the variable
   `RMM_UPDATE_PUBKEY` (the public key) and the secret `RMM_UPDATE_SIGNING_KEY` (the contents of
   `release.key`). Without them the image still builds, but its agents are unsigned and the
   server won't offer them as updates.

## Checklist

1. **Main is green.** All CI jobs on the commit you will tag, in particular `upgrade` (it migrates
   the previous tag's data and reruns the e2e suite) and `e2e-windows`. The `upgrade` job also
   fails if a migration shipped in the previous tag was edited: add a new migration instead.
2. **Bump versions.** `version` under `[workspace.package]` in `Cargo.toml` to the new number
   (then `cargo update -w` or any `cargo check` to refresh `Cargo.lock`). `web/package.json` is
   private and unversioned for releases (`0.0.1`); leave it.
3. **Changelog.** In `CHANGELOG.md` move the `[Unreleased]` entries under a new
   `## [x.y.z] - YYYY-MM-DD` heading, add the compare link at the bottom, and name the newest
   migration if there are new ones (`ls crates/rmm-server/migrations | tail`). Anything an
   operator must do (a new environment variable, a changed default) goes under **Changed** and
   in [OPERATOR.md](OPERATOR.md).
4. **Docs.** `docs/ROADMAP.md`'s "Where things stand" and Done sections, and the README's
   rollback example (`git checkout v…`) if it names a version.
5. **Commit and tag** on `main`, then push both:
   ```sh
   git commit -am "Release v0.2.0"
   git tag -a v0.2.0 -m "v0.2.0: <one line>"
   git push origin main v0.2.0
   ```
6. **Image workflow.** The tag starts "Server image": it builds `ghcr.io/<owner>/<repo>:0.2.0`
   with the Linux and Windows agents, signs them with the release key and writes
   `<binary>.update.json` next to each. Check that the run is green, that `docker pull` works, and
   that the agents are signed (the build log has no "no update_key secret: agents are not signed"
   line).
7. **Verify the signed agents** from the published image:
   ```sh
   docker create --name rel ghcr.io/<owner>/<repo>:0.2.0
   docker cp rel:/srv/agents ./agents && docker rm rel
   cargo run -p rmm-sign -- verify --pubkey <RMM_UPDATE_PUBKEY> agents/rmm-agent-linux-x86_64
   cargo run -p rmm-sign -- verify --pubkey <RMM_UPDATE_PUBKEY> agents/rmm-agent-windows-x86_64.exe
   ./agents/rmm-agent-linux-x86_64 --version     # 0.2.0
   ```
   To sign by hand instead (say, an agent built elsewhere):
   `rmm-sign sign --key release.key --platform linux-x86_64 --version 0.2.0 rmm-agent-linux-x86_64`.
   Signed detection content and signature databases are separate artifacts signed with the same
   key (`rmm-sign sign-content`, `build-db`) and are released on their own timetable.
8. **Upgrade job on the new tag.** The next push to `main` starts the `upgrade` job from the new
   tag. It should be green; if it is red, the failure is in what the *next* commit changed, or in
   the seeding in `crates/rmm-server/tests/upgrade.rs` (which has to keep working against every
   release it can start from: probe for routes the old server may lack).
9. **Roll out.** Update your own deployment first ([OPERATOR.md](OPERATOR.md#upgrades)), then
   offer the agent release: Agents → **Update N outdated**, or turn on **Update agents
   automatically** in the agent policy.
10. **Publish the release notes** (GitHub → Releases → from the tag), pasting the changelog
    section.

## If a release is bad

Don't move or delete a published tag: agents and images may already have it. Fix forward with a
new patch tag. A shipped migration must never be edited. Agents that took a build they can't
connect with roll themselves back after 120 seconds, and automatic updates don't retry a version
that failed on that agent.
