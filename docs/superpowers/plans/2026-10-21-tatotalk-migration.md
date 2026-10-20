# TatoTalk Independent Migration Implementation Plan

> **For agentic workers:** Execute the already authorized migration inline, use independent inventory and portability reviews, and obtain a fresh review before merge.

**Goal:** Preserve the existing TatoTalk research in `D:\tato-catch`, publish reviewed source to `Akiyy-dev/tato-catch`, merge it, and produce an accurately scoped prerelease.

**Architecture:** Keep the existing `research/` layout so relative sample/tool paths continue to work. Preserve large local artifacts but exclude them from Git and release archives; use small evidence fixtures and original scripts for reproducibility.

**Tech Stack:** Python 3.12+, Windows PowerShell, Frida CLI 17.24.3, GitHub Actions.

**Spec:** User instructions in this conversation on 2026-10-21 explicitly authorize migration, review, build, push, merge and release without additional confirmation.

## Constraints and review focus

- Preserve the TG-forwarder branch and all source files; use a fresh destination repository.
- Do not copy the running client's account/profile directory or start live message probes.
- Keep executable SHA/path/code-byte checks, fixed test-marker filtering and bounded detach behavior.
- Clearly distinguish one successful text capture from four unmatched media experiments and unimplemented Linux reception.
- Archive only allowlisted source/docs/fixtures; refuse binaries, private data, unexpected paths and oversized tracked files.

## Tasks

- [x] Copy and hash-verify the research snapshot; change only destination path-dependent scripts.
- [x] Add setup, documentation, curated evidence fixtures, offline checks and a deterministic source archive build.
- [x] Run syntax checks, meaningful packaging tests and local build; audit the staged file list.
- [ ] Obtain independent whole-change review and address blocking findings.
- [ ] Push a feature branch, create and attach a PR, verify CI and merge.
- [ ] Tag the merged commit, publish prerelease artifacts, and verify remote state and asset hashes.

## Execution rulings

- The destination repository was empty and the default branch is `main`; initialize a minimal base, then import on a `dev/` branch for a reviewable PR.
- No new listener or media-capture fix is part of this migration. Historical reports retain original paths and timestamps.
- The source directory remains as a backup. The standalone project becomes the location for future TatoTalk work.
