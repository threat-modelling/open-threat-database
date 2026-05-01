# Contributing

Thanks for wanting to improve the open-threat-database. This catalogue is consumed by real tools, and consumers rely on its structure and identifiers being stable. Please read this before submitting changes.

## What belongs here

**In scope:** generally-applicable threats against software and infrastructure, with clear STRIDE and MITRE ATT&CK mappings and actionable controls. Examples: SQL injection, credential theft, privilege escalation, supply-chain attacks.

**Out of scope:** consumer-specific concepts. If a threat only exists as a modelling construct inside a particular tool's UI (e.g. "this threat applies to connections in a diagram"), that classification belongs in the consumer, not here. This keeps the database useful to any number of tools without forcing them to share domain assumptions.

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
- `severity`: judge based on typical blast radius if the threat is realised without compensating controls. Don't anchor to best-case or worst-case.
- `stride`: list every applicable category, in the canonical order from `schema.ts`.
- `mitreTechniques`: include all directly relevant techniques. Tactic strings match the ATT&CK Enterprise matrix.
- `cwes` (optional): one or more CWE IDs that classify this threat at the weakness level. Strongly preferred for any threat that maps cleanly to CWE — omit only when no CWE is a reasonable fit (e.g. governance threats like Shadow IT). Format `CWE-<digits>`.
- `controls`: prefer concrete, verifiable controls. Avoid generic phrases like "improve security".
- `references` (optional): URLs to authoritative deep-dive guidance (OWASP cheat sheets, NIST publications, vendor security docs, RFCs). Prefer stable canonical sources over blog posts. Two to four high-quality links is the sweet spot.

## Testing

```bash
npm install
npm test
```

Tests validate that IDs are unique, required fields are present, and enum values are from the allowed set.

## Releasing

- Breaking changes (deletions, schema changes): major version bump.
- New threats, new controls on existing threats, additional fields: minor bump.
- Wording fixes, typo corrections: patch bump.

Tag the release (`git tag vX.Y.Z`) so downstream consumers can pin to it.
