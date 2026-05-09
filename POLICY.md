# Engineering Policy

These rules are mandatory for coding changes in this repository.

## Must Rules

- MUST: Keep the project on Go 1.26 across module metadata, CI, Docker builds,
  release packaging, and documentation.
- MUST: Run `make guardrails` before committing or opening a pull request.
- MUST: Keep `.golangci.yml` aligned with the repository guardrail policy and
  run `golangci-lint` through `make lint` or `make guardrails`.
- MUST: Keep `vendor/` synchronized after dependency changes.
- MUST: Prefer unit-driven development for new or changed runtime behavior by
  adding or updating focused unit tests before production wiring whenever the
  behavior can be exercised locally.
- MUST: Add focused regression coverage for bug fixes when a reproducer is
  practical.
- MUST: Keep runtime, Docker, systemd, and README changes aligned when
  operator-facing behavior changes.
- MUST: Document new and changed `contrib/` helper scripts, endpoint test
  clients, and operator-facing tooling in README, including purpose, defaults,
  commands, and side effects.
- MUST: Write code comments and technical documentation in English.
- MUST: Document new and changed functions, methods, and cohesive runtime types,
  including unexported helpers, with English comments that describe their
  responsibility and contracts.
- MUST: Use strict object-oriented design for new and changed code: cohesive
  types, constructor-based dependency injection, encapsulated mutable state, and
  methods on owning structs instead of procedural package-level workflows.
- MUST: Avoid introducing new global mutable state. When touching existing
  global state, prefer moving it behind an explicit service or dependency
  boundary.
- MUST: Keep repeated behavior DRY. Shared parsing, validation, Redis, LDAP,
  GeoIP, logging, and HTTP logic must have one tested implementation instead of
  copied variants.
- MUST: Define interfaces at real package or integration boundaries, not as
  one-off wrappers around a single local implementation.
- MUST: Write commit messages as `Prefix: Concise headline`, using only the
  approved prefixes `Add`, `Change`, `Fix`, `Remove`, `Refactor`, `Test`,
  `Docs`, `Build`, `Ci`, `Vendor`, `Security`, and `Chore`.
- MUST: Use the commit subject as a headline for what was fundamentally done,
  then use the body as a short bullet list of the essential implementation,
  validation, operator-facing, packaging, or dependency details.
- MUST: Split unrelated work into separate commits when no single approved
  prefix and headline describes the change cleanly.

## Definition Of Done

- [ ] Dependency changes were followed by `go mod tidy` and `go mod vendor`.
- [ ] `make guardrails` passes locally.
- [ ] `golangci-lint` findings are fixed or intentionally documented.
- [ ] New or changed runtime behavior has focused unit coverage added or
  updated before the production wiring where practical.
- [ ] New or changed runtime code follows the OOP, dependency-injection, and
  DRY rules above.
- [ ] Operator-facing docs and packaging were updated when behavior changed.
- [ ] New or changed `contrib/` helper scripts, endpoint test clients, and
  operator-facing tooling are documented in README with defaults and side
  effects.
- [ ] New and changed functions, methods, and runtime types have useful English
  comments, including unexported helpers.
- [ ] Commit messages use the approved prefix, headline, and bullet-list body
  format.
