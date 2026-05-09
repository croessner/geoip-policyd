# geoip-policyd Development Guidelines

This repository is a vendored Go 1.26 project. Keep `go.mod`, Docker builds,
CI, release packaging, and operator-facing documentation aligned with Go 1.26
whenever toolchain details change.

## Required Workflow

- Use the Makefile targets instead of ad hoc command variants whenever possible.
- Run `make guardrails` before every commit or pull request.
- Run lint through `make lint`; `make guardrails` includes `golangci-lint`.
- Keep the vendored module tree in sync. After dependency updates, run
  `go mod tidy` and `go mod vendor`.
- Add focused regression tests for bug fixes before changing production code
  when a reproducer is practical.
- Keep runtime, Docker, systemd, and README changes aligned when operator-facing
  behavior changes.
- Write code comments and technical documentation in English.

## Commit Log Format

Use structured commit messages with a fixed, capitalized prefix and a concise
headline:

```text
Prefix: Summarize the main change

- Detail the most relevant implementation work
- Mention tests, guardrails, or generated files when relevant
- Call out operator-facing behavior, config, packaging, or dependency changes
```

Allowed prefixes:

- `Add`: new functionality, files, or supported behavior
- `Change`: behavior changes that are not primarily bug fixes
- `Fix`: bug fixes and regressions
- `Remove`: deleted behavior, files, or obsolete paths
- `Refactor`: internal restructuring without intended behavior changes
- `Test`: test-only changes
- `Docs`: documentation-only changes
- `Build`: Makefile, Docker, packaging, release, or toolchain changes
- `Ci`: GitHub Actions, GitLab CI, or automation changes
- `Vendor`: dependency and vendored module updates
- `Security`: hardening or vulnerability-related changes
- `Chore`: repository maintenance that does not fit the other prefixes

The subject line should state what was fundamentally done. The body should be a
short bullet list that refines the headline with the essential work completed.
Split unrelated work into separate commits when no single prefix and headline
describe the change cleanly.

## Design Principles

- Use strict object-oriented design for new and changed code. Model runtime
  behavior as cohesive types with explicit responsibilities, constructor-based
  dependency injection, and methods on those types instead of expanding
  procedural package-level workflows.
- Keep mutable state encapsulated in owning structs. Do not introduce new global
  mutable state; when touching existing global state, prefer moving it behind an
  explicit service or dependency boundary.
- Define interfaces at package or integration boundaries where they reduce
  coupling or enable focused tests. Avoid interfaces that only duplicate one
  local implementation without a boundary.
- Apply DRY deliberately. Shared parsing, validation, Redis, LDAP, GeoIP,
  logging, and HTTP behavior should live in one tested implementation instead of
  being copied between commands, handlers, or tests.
- Prefer small, focused helpers over broad abstractions. DRY is mandatory for
  repeated behavior, but abstractions must still make the resulting code easier
  to read, test, and maintain.

## Quality Gates

`make guardrails` runs the local quality gate:

- `make fix`
- `make vet`
- `make lint`
- `make test`
- `make race`
- `make build-check`
