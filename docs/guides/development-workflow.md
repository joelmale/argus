---
id: development-workflow
title: Development Workflow Guide
sidebar_position: 14
---

# Development Workflow Guide

Argus now has a clearer separation between:

- pull request validation
- continuous image publishing from `main`
- formal release publishing

Because of that, `main` should be treated as the integration branch, not as a personal development branch.

## Why Branches Matter Now

Pushing directly to `main` now has operational consequences:

- it publishes fresh `main` container images to GHCR
- it publishes SHA-tagged images that can be deployed by Dockhand
- it can trigger security scanning and signing for those images

That means `main` is no longer just "the place code lives." It is now part of the delivery pipeline.

If you develop directly on `main`, you lose several controls:

- no PR review checkpoint
- no isolated validation cycle before integration
- higher chance of publishing broken or half-finished images
- weaker rollback discipline and change tracking

## Recommended Development Policy

Use short-lived branches for all normal work.

Recommended flow:

1. create a branch from `main`
2. make and test changes on that branch
3. open a pull request into `main`
4. let PR checks validate the affected areas
5. merge only after the PR is in acceptable shape
6. let the `main` push publish updated images
7. create a tagged GitHub Release only when you want a versioned release

Recommended branch naming patterns:

- `feature/topology-layout`
- `fix/scan-offline-scope`
- `chore/workflow-cleanup`
- `docs/settings-reference`

## Workflow Summary

### PR Checks

File:

- [`.github/workflows/pr-checks.yml`](../../.github/workflows/pr-checks.yml)

Trigger:

- pull requests targeting `main`

Purpose:

- validate code before it reaches `main`
- avoid spending CI time on unrelated areas

What it does:

- detects changed areas in the repo
- runs backend quality only when backend or shared files changed
- runs frontend quality only when frontend or shared files changed
- runs docs build only when docs or shared files changed
- cancels older in-progress PR runs when new commits are pushed to the same PR

Use it when:

- opening or updating a pull request
- validating that a branch is ready to merge

### Release Images

File:

- [`.github/workflows/release-images.yml`](../../.github/workflows/release-images.yml)

Triggers:

- push to `main`
- push of version tags like `v1.5.0`
- manual dispatch

Purpose:

- build deployable backend, scanner, and frontend images
- scan them for high/critical vulnerabilities
- sign them
- publish them to GHCR

What it publishes:

- `main` tag for default-branch builds
- `sha-<shortsha>` tags for traceable builds
- semantic version tags for version-tag pushes

Use it when:

- merging validated work into `main`
- cutting a version tag for a rollback-friendly release image set

### Publish Release Assets

File:

- [`.github/workflows/publish.yml`](../../.github/workflows/publish.yml)

Triggers:

- published GitHub Releases
- manual dispatch

Purpose:

- build the docs site
- deploy docs to GitHub Pages
- attach release-facing archives to the GitHub Release

What it publishes:

- GitHub Pages docs output from `website/`
- docs archive
- clean source archive

Use it when:

- making a formal release
- publishing versioned documentation and release assets

## Practical Operating Model

For normal development:

1. create a feature or fix branch
2. push commits to that branch
3. open a PR
4. let `PR Checks` validate the branch
5. merge to `main`
6. let `Release Images` publish the new `main` and `sha-*` images

For a formal versioned release:

1. merge the desired state into `main`
2. create a version tag such as `v1.5.0`
3. publish a GitHub Release for that tag
4. let `Release Images` publish semver image tags
5. let `Publish Release Assets` deploy docs and attach archives

## When Direct Pushes To `main` Are Acceptable

Direct pushes to `main` should be the exception, not the default.

Reasonable exceptions:

- urgent production fix with no time for a normal PR cycle
- repository-admin maintenance work
- narrowly scoped workflow or documentation repair when you intentionally accept immediate publication behavior

Even in those cases, remember that a push to `main` is now a publishing event.

## Recommended Team Rule

Treat `main` as:

- stable enough to publish
- review-worthy
- deployable by default

Treat branches as:

- the place to experiment
- the place to iterate
- the place to fail cheaply before publishing artifacts

## Related Files

- [`.github/workflows/pr-checks.yml`](../../.github/workflows/pr-checks.yml)
- [`.github/workflows/release-images.yml`](../../.github/workflows/release-images.yml)
- [`.github/workflows/publish.yml`](../../.github/workflows/publish.yml)
- [CI/CD Security Guide](./ci-cd-security.md)
