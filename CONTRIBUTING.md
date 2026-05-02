# Contributing

Thanks for wanting to improve the open-threat-database. This catalogue is consumed by real tools, and consumers rely on its structure and identifiers being stable. Please read this before submitting changes.

## What belongs here

**In scope:** generally-applicable threats against software and infrastructure, with clear STRIDE and MITRE ATT&CK mappings and actionable controls. Examples: SQL injection, credential theft, privilege escalation, supply-chain attacks.

**Out of scope:** consumer-specific concepts. If a threat only exists as a modelling construct inside a particular tool's UI (e.g. "this threat applies to connections in a diagram"), that classification belongs in the consumer, not here. This keeps the database useful to any number of tools without forcing them to share domain assumptions.

## Adding a threat

Edit `src/threats.json`. Each threat must match the schema in `src/schema.ts`:

```json
{
  "id": "kebab-case-id",
  "name": "Human Readable Name",
  "description": "One-paragraph description of the threat and how it manifests.",
  "severity": "low | medium | high | critical",
  "stride": ["tampering", "information-disclosure"],
  "mitreTechniques": [
    { "id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access" }
  ],
  "cwes": ["CWE-89"],
  "controls": [
    { "id": "ctrl-shortname-1", "description": "Actionable mitigation." }
  ],
  "references": [
    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
  ]
}
```

Conventions:

- `id`: kebab-case, descriptive, 2–5 words. Use existing IDs as a guide.
- `controls[].id`: `ctrl-{threat-shortname}-{number}`, numbered sequentially within the threat.
- `severity`: assigned per the [Severity rubric](#severity-rubric) below. Judge typical blast radius without compensating controls — not best-case, not worst-case.
- `stride`: list every applicable category, in the canonical order from `schema.ts`.
- `mitreTechniques`: include all directly relevant techniques. Tactic strings match the ATT&CK Enterprise matrix.
- `cwes` (optional): one or more CWE IDs that classify this threat at the weakness level. Strongly preferred for any threat that maps cleanly to CWE — omit only when no CWE is a reasonable fit (e.g. governance threats like Shadow IT). Format `CWE-<digits>`.
- `controls`: prefer concrete, verifiable controls. Avoid generic phrases like "improve security".
- `references` (optional): URLs to authoritative deep-dive guidance (OWASP cheat sheets, NIST publications, vendor security docs, RFCs). Prefer stable canonical sources over blog posts. Two to four high-quality links is the sweet spot.

## Severity rubric

Severity ranks the **intrinsic impact** of a threat being realised without compensating controls. The catalogue cannot know the likelihood of exploitation in any particular environment, so likelihood is deliberately not weighted — only impact is. The four levels are anchored to [CVSS v3.1](https://www.first.org/cvss/v3-1/specification-document) qualitative bands so a contributor can sanity-check a rating against a known industry standard.

When more than one tier could fit, **pick the highest** that applies.

### Critical

Any of:

- Direct, persistent privileged execution on a host or control plane: root, SYSTEM, container host, cluster admin, cloud account or organisation admin, KMS key holder.
- Disclosure of "kingdom keys" — long-lived credentials, tokens, certificates, or secrets that *themselves* grant the privileged tier above (cluster certificates, etcd snapshots, root API keys, broad service-account keys).
- Wholesale loss of integrity or availability of tenant data: mass deletion, ransom encryption, control-plane wipe, destruction of backups.

CVSS-equivalent: typically C:H/I:H/A:H, often scope-changed; CVSS ≥ 9.0.

### High

Any of:

- Initial code execution or full compromise of a single workload, service, or account at non-privileged level, with realistic abuse paths to escalate.
- Theft of credentials, tokens, or session material that grants access to other systems but **not** directly to the privileged tier above.
- Authentication or authorisation bypass that exposes substantial protected data or functionality.
- Lateral pivot capability that enables — but does not by itself constitute — a privileged compromise.

CVSS-equivalent: typically two of C/I/A at High, scope unchanged; CVSS 7.0–8.9.

### Medium

Any of:

- Unauthorised read or modification of protected application data without obtaining execution or credentials.
- Design or configuration weakness that **expands the blast radius** of other threats but is not by itself directly exploitable for access (excessive permissions, weak segmentation, unpatched non-critical CVEs).
- Tampering with messages, events, or workflows in transit or at processing time, without persistent access.

CVSS-equivalent: one of C/I/A at High, or two at Low; CVSS 4.0–6.9.

### Low

Any of:

- Repudiation: ability to deny or obscure an authorised action without altering data integrity (e.g. logging bypass with no further chained effect).
- Low-impact information disclosure: internal hostnames, version banners, fingerprintable error messages.
- Volumetric availability impact only — service is degraded but no confidentiality or integrity loss.

CVSS-equivalent: CVSS 0.1–3.9.

### Tie-breakers and anti-patterns

- **Credential disclosure tiers on what the credential unlocks.** An AWS root key is Critical. A single user's app password is High. A read-only API token to non-sensitive endpoints is Medium.
- **Don't escalate by reputation.** "Ransomware" sounds scary, but the rating still has to come from the rubric (in its case: wholesale data integrity and availability loss → Critical).
- **Severity is per threat *class*, not per worst-known instance.** `unpatched-vulnerabilities` is rated on the category's typical blast radius, not the worst CVE that ever shipped under that label.
- **Don't weight likelihood, exploitability, or detection difficulty.** Those are environmental — the catalogue ranks impact only.

## The ID-stability contract

Threat `id` and control `id` values are **permanent once released**. Consumers store these IDs in their own data (user threat models, severity overrides, "control implemented" checkboxes), so renames silently break user data.

Rules:

- **Additions are always safe.** Adding a new threat or a new control to an existing threat is a minor version bump.
- **Renames require deprecation.** If a threat or control must be renamed, move the old ID into the `aliases` array on the renamed entity. `getThreatById` resolves aliases transparently, so consumers that have the old ID stored continue to work. Keep the alias in place for at least one minor release before considering removal.
- **Deletions are breaking changes** and require a major version bump plus a migration note in the changelog. Removing an alias is also a breaking change.
- **Wording changes to `name`, `description`, or `controls[].description` are fine** — these are not stable identifiers.

Example — suppose a hypothetical threat originally named `csrf` is renamed to `csrf-attack` for consistency with other `-attack` IDs. The renamed entry would look like:

```json
{
  "id": "csrf-attack",
  "aliases": ["csrf"],
  "name": "Cross-Site Request Forgery",
  ...
}
```

`getThreatById('csrf')` would then continue to return the renamed threat. Aliases must not collide with any primary ID or any other alias — the test suite enforces this.

### Stable identifiers and aliases

`id` values on threats and controls are permanent. If a threat is renamed, the old ID is preserved in `aliases` and `getThreatById('old-id')` continues to return the renamed threat.

## Testing

```bash
npm install
npm test
```

Tests validate that IDs are unique, required fields are present, and enum values are from the allowed set.

## Previewing on the site

The catalogue is published to GitHub Pages on each release. To preview your edits as they will appear there:

```bash
npm run dev:site      # build, serve at http://localhost:8080/, auto-reload on edits
npm run preview:site  # build and serve once, no watch
```

Override the port with `PORT=4321 npm run dev:site`. The generated `site/` directory is a build artifact and is gitignored.

## Releasing

### Package version bump guidance
- Breaking changes (deletions, schema changes): major version bump.
- New threats, new controls on existing threats, additional fields: minor bump.
- Severity re-grades (see the [Severity rubric](#severity-rubric)): minor bump. Severity isn't an ID, but consumers filter and sort on it, so any change must be called out in the changelog with the old → new value.
- Wording fixes, typo corrections: patch bump.

### Expected package metadata

The fields in `package.json` are part of the release contract:

| Field | Purpose |
|-------|---------|
| `name`, `version` | npm-required; version bumps follow [the semver policy](./CONTRIBUTING.md#releasing). |
| `description`, `keywords` | npm search discoverability. |
| `repository`, `homepage`, `bugs` | Link the npm listing back to GitHub. |
| `license`, `author` | MIT. |
| `type`, `main`, `types` | ES module entry points and TypeScript types. |
| `exports["."]` | Public JS/TS entry point — consumers `import` from `open-threat-database`. |
| `exports["./schema.json"]` | Exposes the JSON Schema at `open-threat-database/schema.json` for non-JS consumers. |
| `files` | Only `dist/` is shipped — source and tests are excluded. |
| `engines.node` | Minimum supported Node version (currently `>=18`). |
| `scripts.build` | Must produce `dist/threats.json` and `dist/schema.json`; the release workflow attaches both. |

When editing metadata:

- Do not remove or rename existing `exports` entries — both `open-threat-database` and `open-threat-database/schema.json` are public and consumers depend on them.
- Do not drop `engines.node` below a Node LTS that is still in active support.
- Adding new keywords or expanding the description is always safe.
