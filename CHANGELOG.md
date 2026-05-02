# Changelog

All notable changes to `@threat-modelling/open-threat-database` are recorded here.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [semantic versioning](./CONTRIBUTING.md#releasing). Severity re-grades are minor bumps and listed under **Changed** with the old → new value.

## [0.2.0] - 2026-05-02

### Added
- Severity rubric: a four-tier (Critical / High / Medium / Low) impact-only rating system anchored to CVSS v3.1 qualitative bands. Documented in [`CONTRIBUTING.md`](./CONTRIBUTING.md#severity-rubric) for contributors and on the published site at `/severity/` for consumers. The schema description and README now reference the rubric.
- `Severity` page in the GitHub Pages site, with anchor links per tier (`#critical`, `#high`, `#medium`, `#low`). Severity badges on each threat detail page link to the corresponding tier.
- Versioning policy: severity re-grades are minor version bumps and must be listed in this changelog.

### Changed — severity re-grades
Sweep of the existing catalogue against the new rubric. Five threats were re-graded:

- `backup-exposure`: medium → **high**. An exposed database backup is wholesale data exposure of the entire dataset, fitting the High criterion ("authentication or authorisation bypass that exposes substantial protected data").
- `broken-authentication`: medium → **high**. The threat is, by definition, authentication bypass exposing user accounts and protected data — sits squarely in High.
- `account-takeover`: critical → **high**. Generic class compromises a single user account. The rubric's tie-breaker ("a single user's app password is High") applies. Privileged-account takeover would tier on its own facts but is not the typical class.
- `credential-theft`: critical → **high**. Generic credential theft fits High ("credentials/tokens that grant access to other systems but not directly to the privileged tier"). Kingdom-key cases (cluster certs, root keys) are already covered by separate Critical threats (`kubernetes-secrets-exposure`, `etcd-snapshot-exposure`).
- `prompt-injection`: critical → **high**. Typical realisation is safety-control bypass and context exfiltration. The privileged-AI-agent case (Critical-tier impact) is environment-specific and matches the rubric's note about not anchoring to worst case.

No threat IDs, control IDs, or schema fields changed.

## [0.1.2] and earlier

No changelog was kept prior to this release. See the [git history](https://github.com/threat-modelling/open-threat-database/commits/main) for changes before the rubric was introduced.
