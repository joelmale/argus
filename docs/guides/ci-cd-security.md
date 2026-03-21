---
id: ci-cd-security
title: CI/CD Security Guide
sidebar_position: 13
---

# CI/CD Security Guide

Argus uses GitHub Actions to enforce quality and security gates before code reaches production images, and before production images are pulled by Dockhand.

This pipeline is designed as a layered control system rather than a single pass/fail check. Each gate reduces a different class of delivery risk:

- correctness risk: broken tests, failed builds, invalid docs
- quality risk: maintainability regressions and unsafe code patterns
- supply-chain risk: vulnerable OS or package layers inside published images
- release integrity risk: unsigned or ambiguous images
- deployment drift risk: Dockhand pulling mutable or locally built artifacts instead of versioned images

## Control Objectives

| Control | Primary Risk Reduced | Delivery Stage |
|---|---|---|
| backend tests and lint | functional regressions, unsafe refactors | pull request |
| frontend lint, type-check, build | UI/runtime regressions | pull request |
| docs build | broken operator guidance and deployment docs | pull request |
| SonarQube analysis | code-quality debt and code-level security findings | pull request and `main` |
| image build in CI | non-reproducible server-side builds | merge to `main` |
| Trivy image scan | vulnerable packages in release artifacts | merge to `main` |
| Cosign signing | image tampering and provenance ambiguity | merge to `main` |
| GHCR versioned tags | rollback and traceability failure | merge to `main` |
| Dockhand image-tag deployment | source/build drift on deployment host | deploy |

## Pipeline Overview

```mermaid
flowchart LR
  PR[Pull Request] --> PRChecks[PR Checks]
  PRChecks --> Sonar[SonarQube Analysis]
  Sonar --> Merge[Merge to main]
  Merge --> Build[Build OCI Images]
  Build --> Trivy[Trivy Image Scan]
  Trivy --> Sign[Cosign Keyless Sign]
  Sign --> GHCR[Push Versioned Images to GHCR]
  GHCR --> Dockhand[Dockhand Pulls Image Tags]
  Dockhand --> Prod[Production Runtime]
```

## Pull Request Gates

Pull requests run three classes of preventative controls:

- backend quality: `ruff`, migrations, and backend tests with coverage
- frontend quality: ESLint, TypeScript type-checking, and production build
- docs quality: Docusaurus build of the operator documentation site

These are designed to catch delivery failures before they become deployment artifacts.

## SonarQube Gate

SonarQube runs on pull requests and on `main`.

From a risk-management perspective, SonarQube is the code-level assurance gate. It complements tests by looking for:

- maintainability degradation
- suspicious control flow or unsafe patterns
- code smells that increase future change risk
- security hotspots and static-analysis findings that tests would not naturally exercise

The intended operating model is:

- developers review Sonar findings during PRs
- branch protection requires the Sonar workflow to pass before merge
- the quality gate acts as a policy control, not just an informational report

## Release Artifact Controls

After merge to `main`, GitHub Actions builds:

- `argus-backend`
- `argus-scanner`
- `argus-frontend`

Each image is:

1. tagged with `main`
2. tagged with the Git commit SHA
3. scanned by Trivy
4. signed by Cosign using GitHub OIDC
5. pushed to GHCR

This moves release creation into CI so the deployment host is no longer responsible for building application code.

## Image Security Gate

Trivy scans each built image and fails the release workflow on `HIGH` or `CRITICAL` findings.

That gate is primarily about release acceptance risk:

- do not promote artifacts with severe known vulnerabilities
- avoid normalizing “ship now, patch later” on critical package risk
- attach SARIF results into GitHub so security review has a durable trail

```mermaid
flowchart TD
  Image[Built Image] --> Scan[Trivy Scan]
  Scan -->|No HIGH/CRITICAL findings| Sign[Cosign Sign]
  Scan -->|HIGH/CRITICAL findings| Block[Release Blocked]
  Sign --> Publish[Push to GHCR]
```

## Provenance and Signing

Cosign keyless signing gives each image a verifiable integrity marker tied to the GitHub Actions identity that produced it.

This reduces:

- ambiguity about who built the image
- risk of untrusted replacement artifacts
- rollback confusion when multiple artifacts share a weak tag name

Operators should prefer immutable SHA-tagged images in Dockhand when they want strong rollout traceability.

## Dockhand Deployment Model

Dockhand should deploy published images, not build the repo.

Recommended model:

- `docker-compose.yml` points at GHCR images
- Dockhand overrides image tags or image variables as needed
- production hosts pull signed images by tag

This separates:

- build trust boundary: GitHub Actions
- runtime trust boundary: Dockhand / production host

That separation is important for risk containment. If a deployment host is compromised or misconfigured, it should not also be your build system.

## Required GitHub Configuration

### Repository secrets

- `SONAR_TOKEN`

### Repository variables

- `SONAR_PROJECT_KEY`
- `SONAR_HOST_URL`
- `SONAR_ORGANIZATION`

`SONAR_ORGANIZATION` is mainly relevant for SonarQube Cloud / SonarCloud style setups. Self-hosted SonarQube Server deployments may not need it.

## Required Dockhand Variables

To consume CI-built images in production, set image references explicitly if you want immutable deployments:

- `ARGUS_BACKEND_IMAGE`
- `ARGUS_SCANNER_IMAGE`
- `ARGUS_FRONTEND_IMAGE`

Recommended pattern:

- `ARGUS_BACKEND_IMAGE=ghcr.io/joelmale/argus-backend:sha-<commit>`
- `ARGUS_SCANNER_IMAGE=ghcr.io/joelmale/argus-scanner:sha-<commit>`
- `ARGUS_FRONTEND_IMAGE=ghcr.io/joelmale/argus-frontend:sha-<commit>`

If you use the floating `main` tag instead, deployments are simpler but rollback and forensic traceability are weaker.

## Risk Framing Summary

| Threat / Failure Mode | Primary Control |
|---|---|
| merge breaks backend behavior | backend PR checks |
| merge breaks frontend runtime | frontend PR checks |
| docs drift from reality | docs build gate |
| weak code enters protected branch | SonarQube quality gate |
| vulnerable package ships in release image | Trivy |
| deployment host builds a different artifact than CI | GHCR image publish model |
| image authenticity is unclear | Cosign signing |
| production rollout is hard to trace or roll back | SHA-tagged images |

## Related Files

- [`.github/workflows/pr-checks.yml`](../../.github/workflows/pr-checks.yml)
- [`.github/workflows/sonarqube.yml`](../../.github/workflows/sonarqube.yml)
- [`.github/workflows/release-images.yml`](../../.github/workflows/release-images.yml)
- [`docker-compose.yml`](../../docker-compose.yml)
- [`.env.production`](../../.env.production)
