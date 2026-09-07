# Maintenance review — 2026-09-07

## Scope and provenance

The supplied export was treated as untrusted data. The checkout was clean on `main`,
with origin `git@github.com:croessner/geoip-policyd.git` and HEAD
`b5e5aa25193b0979ce0eee4d5d044af80e941176`. GitHub independently returned the same
default-branch SHA, a non-archived repository, and latest release `v2.0.0`
published on 2026-05-25. The local `v2.0.0` tag points at HEAD.

The fresh Trivy 0.74.0 scan used vulnerability DB updated 2026-09-07 19:06 UTC
and refreshed the checks bundle on 2026-09-07. Original Go vulnerability JSON
records, the gRPC maintainer advisory, the gRPC 1.83.1 release, and the CVE CNA
record were fetched separately. Scanner evidence and logs are retained locally
under `/tmp/geoip-maint/`; this directory is temporary, not a durable CI artifact.

## Dependency findings

“Fixed” below means the affected module version was replaced and the finding
disappeared in the fresh scan; it does not claim the old application exposed
every upstream vulnerability. The pre-update call analysis reported gRPC
transport symbols, while SSH and OpenPGP packages were absent. IDNA and Unicode
normalization were imported without reported vulnerable calls. OpenTelemetry
used TraceContext propagation, not Baggage extraction. Static call traces are
not a demonstrated exploit or evidence of production configuration.

| Severity | Finding | Original source | Result |
|---|---|---|---|
| CRITICAL | CVE-2026-56854 | [Go GO-2026-6303](https://vuln.go.dev/ID/GO-2026-6303.json) | Fixed by dependency update. |
| HIGH | CVE-2026-39828 | [Go GO-2026-5014](https://vuln.go.dev/ID/GO-2026-5014.json) | Fixed by dependency update. |
| HIGH | CVE-2026-39829 | [Go GO-2026-5018](https://vuln.go.dev/ID/GO-2026-5018.json) | Fixed by dependency update. |
| HIGH | CVE-2026-39830 | [Go GO-2026-5017](https://vuln.go.dev/ID/GO-2026-5017.json) | Fixed by dependency update. |
| HIGH | CVE-2026-39831 | [Go GO-2026-5019](https://vuln.go.dev/ID/GO-2026-5019.json) | Fixed by dependency update. |
| HIGH | CVE-2026-39832 | [Go GO-2026-5006](https://vuln.go.dev/ID/GO-2026-5006.json) | Fixed by dependency update. |
| HIGH | CVE-2026-39835 | [Go GO-2026-5015](https://vuln.go.dev/ID/GO-2026-5015.json) | Fixed by dependency update. |
| HIGH | CVE-2026-42508 | [Go GO-2026-5021](https://vuln.go.dev/ID/GO-2026-5021.json) | Fixed by dependency update. |
| HIGH | CVE-2026-46595 | [Go GO-2026-5023](https://vuln.go.dev/ID/GO-2026-5023.json) | Fixed by dependency update. |
| HIGH | CVE-2026-46597 | [Go GO-2026-5013](https://vuln.go.dev/ID/GO-2026-5013.json) | Fixed by dependency update. |
| MEDIUM | CVE-2026-39827 | [Go GO-2026-5016](https://vuln.go.dev/ID/GO-2026-5016.json) | Fixed by dependency update. |
| MEDIUM | CVE-2026-39833 | [Go GO-2026-5005](https://vuln.go.dev/ID/GO-2026-5005.json) | Fixed by dependency update. |
| MEDIUM | CVE-2026-39834 | [Go GO-2026-5020](https://vuln.go.dev/ID/GO-2026-5020.json) | Fixed by dependency update. |
| MEDIUM | CVE-2026-46598 | [Go GO-2026-5033](https://vuln.go.dev/ID/GO-2026-5033.json) | Fixed by dependency update. |
| UNKNOWN | CVE-2026-56855 | [Go GO-2026-6355](https://vuln.go.dev/ID/GO-2026-6355.json) | Fixed by dependency update. |
| UNKNOWN | CVE-2026-78662 | [Go GO-2026-6354](https://vuln.go.dev/ID/GO-2026-6354.json) | Fixed by dependency update. |
| UNKNOWN | GO-2026-5932 | [Go GO-2026-5932](https://vuln.go.dev/ID/GO-2026-5932.json) | Not applicable: OpenPGP is neither vendored nor imported; module-level warning remains. |
| HIGH | CVE-2026-25681 | [Go GO-2026-5029](https://vuln.go.dev/ID/GO-2026-5029.json) | Fixed by dependency update. |
| HIGH | CVE-2026-27136 | [Go GO-2026-5030](https://vuln.go.dev/ID/GO-2026-5030.json) | Fixed by dependency update. |
| HIGH | CVE-2026-39821 | [Go GO-2026-5026](https://vuln.go.dev/ID/GO-2026-5026.json) | Fixed by dependency update. |
| HIGH | CVE-2026-46600 | [Go GO-2026-5942](https://vuln.go.dev/ID/GO-2026-5942.json) | Fixed by dependency update. |
| MEDIUM | CVE-2026-25680 | [Go GO-2026-5028](https://vuln.go.dev/ID/GO-2026-5028.json) | Fixed by dependency update. |
| MEDIUM | CVE-2026-42502 | [Go GO-2026-5027](https://vuln.go.dev/ID/GO-2026-5027.json) | Fixed by dependency update. |
| MEDIUM | CVE-2026-42506 | [Go GO-2026-5025](https://vuln.go.dev/ID/GO-2026-5025.json) | Fixed by dependency update. |
| HIGH | CVE-2026-56852 | [Go GO-2026-5970](https://vuln.go.dev/ID/GO-2026-5970.json) | Fixed by dependency update. |
| HIGH | CVE-2026-84304 | [CNA record](https://cveawg.mitre.org/api/cve/CVE-2026-84304) | Fixed by dependency update. |
| HIGH | GHSA-hrxh-6v49-42gf | [gRPC advisory](https://github.com/grpc/grpc-go/security/advisories/GHSA-hrxh-6v49-42gf) | Fixed by dependency update. |

The additional [GO-2026-5158](https://vuln.go.dev/ID/GO-2026-5158.json)
(CVE-2026-41178, OpenTelemetry baggage limits) was absent from the supplied
export and identified by govulncheck. The affected module was also updated.

| Dependency | Before | After |
|---|---|---|
| golang.org/x/crypto | 0.51.0 | 0.56.0 |
| golang.org/x/net | 0.53.0 | 0.57.0 |
| golang.org/x/text | 0.37.0 | 0.41.0 |
| google.golang.org/grpc | 1.80.0 | 1.83.1 |
| OpenTelemetry modules | 1.43.0 | 1.44.0 |

The newer x/net, x/text and x/sys versions follow the requirements of x/crypto
0.56.0; grpc-gateway and genproto follow gRPC requirements. `go mod tidy` also
corrected the direct/indirect classification of imports used by the smoke client.
`go mod tidy` and `go mod vendor` completed with Go 1.26.8.

## Container and toolchain findings

| Finding and path | Result |
|---|---|
| DS-0002, Dockerfile | Fixed: runtime USER 10001:10001; mounted-file access requirements documented. |
| DS-0001, Dockerfile | Fixed: explicit Alpine 3.23 runtime release instead of implicit latest. |
| DS-0013, Dockerfile | Fixed: WORKDIR replaces RUN cd. |
| DS-0026, Dockerfile | Still affected: no built-in health check. A listener-aware check remains operator work; process presence is not readiness. |
| DS-0002 and DS-0026, vendor/github.com/pelletier/go-toml/v2/Dockerfile | Not applicable to this image: upstream auxiliary Dockerfile is never built by project workflows. |
| DS-0002 and DS-0026, vendor/go.opentelemetry.io/otel/dependencies.Dockerfile | Not applicable to this image: upstream tooling image references, not a project runtime image. |
| Go 1.26 to 1.27.1 suggestion | Not applicable as a mandatory major/minor upgrade: project policy requires Go 1.26. Updated module minimum, GitHub CI, GitLab CI, release packaging and Docker to 1.26.8. |

Trivy rule definitions were checked against the fresh scanner output and Aqua
rule pages. No blanket ignore file or scanner suppression was introduced.
The host Go 1.27.1 is not used as proof of the release toolchain: validation
explicitly selects Go 1.26.8, listed in the [Go release feed](https://go.dev/dl/?mode=json).

The Docker build also fixes an independently confirmed release defect:
GOARCH was hard-coded to amd64 and the final stage used BUILDPLATFORM even
though workflows requested amd64 and arm64. Both executables now use TARGETOS
and TARGETARCH; the final image uses the requested target platform.

## Release readiness and remaining work

The reported 293 unreleased commits compare against the historical
`v2021.0.12` tag, not the current [v2.0.0 release](https://github.com/croessner/geoip-policyd/releases/tag/v2.0.0).
There were zero commits after v2.0.0 before this maintenance. Proposed next
version: **v2.0.1**, optionally **v2.0.1-rc.1** for validating the container UID
and multi-architecture packaging changes before stable publication.

GitHub reported zero open non-PR issues. Previous v2.0.0 release and Docker
workflows succeeded, but did not validate these uncommitted changes. Unit CI
previously only targeted features; main push and PR events are now included.
No push, commit, tag, release publication or deployment was performed.

Release still requires successful CI on the final reviewed commit, packaging
validation of release assets, and a deployment-specific check that the new UID
can read mounted configuration and private keys. The built-in healthcheck gap
remains explicit. GitLab execution was not verified against a remote GitLab
service. Published/deployed binaries were not inspected.

## Validation

- `make guardrails` with `GOTOOLCHAIN=go1.26.8`: passed (fix, vet, lint,
  unit tests, race tests, vendored build). Lint reported zero issues.
- `make smoke-observability`: passed against a real local child process and
  fake Redis/OTLP endpoints; HTTP request, metrics and trace graph validated.
  The first cold/parallel build exceeded the helper's 30-second timeout;
  the completed repeat passed. An earlier guardrail attempt overlapped vendor
  regeneration and failed on transient missing files; the sequential rerun
  passed after vendor synchronization completed.
- `govulncheck ./...` with Go 1.26.8: zero called or imported vulnerabilities;
  one module-only warning (unimported OpenPGP).
- Fresh Trivy filesystem scan: only GO-2026-5932, the project DS-0026 and
  four non-runtime vendor Dockerfile findings remain.
- Both local Docker builds passed: linux/amd64 and linux/arm64. Image metadata
  confirms the requested architecture and USER 10001:10001. No images pushed.
  Both bundled executables started successfully as UID 10001 on both platforms
  with networking disabled, checking their documented usage output and expected
  exit status. This verifies executable startup, not a deployed service path.
- Trivy scan of the built AMD64 image: Alpine 3.23.5 has zero reported OS
  vulnerabilities; the policy binary only retains the module-only OpenPGP
  warning; the stress client has zero findings. ARM64 image vulnerability
  scanning is not claimed.
- `git diff --check`: passed. No application runtime source edits were needed;
  existing unit/race/integration tests cover the dependency update. CI test
  coverage was expanded to main rather than duplicating upstream library tests.
- GitHub coverage: Dependabot alerts disabled (403); Code Scanning has no
  analysis (404); Secret Scanning returned zero alerts, which does not establish
  historical scan coverage or replace a dedicated secret audit.

Changed project files: `go.mod`, `go.sum`, regenerated `vendor/`, `Dockerfile`,
`.github/workflows/build-stable.yaml`, `.github/workflows/unit_tests.yaml`,
`.gitlab-ci.yml`, `README.md`, and this report. Runtime systemd configuration
remains consistent with its existing non-root DynamicUser setup.

## v2.0.1 release preparation follow-up

The user selected v2.0.1 and subsequently authorized implementing the release.
Both architecture images passed HTTP readback of custom settings while running
as UID 10001 with read-only bind mounts for the public GeoIP test database and
a dedicated custom-settings fixture. External networking was disabled; the
temporary containers were stopped afterward. This verifies the documented
container mount contract, not permissions on production secrets or mounts.

Release preparation also updates `.chglog/config.yml` to recognize the
repository's approved commit prefixes. Changelog generation selects the triggering
tag explicitly, and release artifact downloads select the current workflow run.
The remaining deployment-specific checks and scanner-coverage gaps above remain
operator watchpoints; release publication does not deploy the service.
