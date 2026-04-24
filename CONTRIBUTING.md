# Contributing

Thanks for wanting to improve the open-threat-database. This catalogue is consumed by real tools, and consumers rely on its structure and identifiers being stable. Please read this before submitting changes.

## What belongs here

**In scope:** generally-applicable threats against software and infrastructure, with clear STRIDE and MITRE ATT&CK mappings and actionable controls. Examples: SQL injection, credential theft, privilege escalation, supply-chain attacks.

**Out of scope:** consumer-specific concepts. If a threat only exists as a modelling construct inside a particular tool's UI (e.g. "this threat applies to connections in a diagram"), that classification belongs in the consumer, not here. This keeps the database useful to any number of tools without forcing them to share domain assumptions.

## The ID-stability contract

Threat `id` and control `id` values are **permanent once released**. Consumers store these IDs in their own data (user threat models, severity overrides, "control implemented" checkboxes), so renames silently break user data.

Rules:

- **Additions are always safe.** Adding a new threat or a new control to an existing threat is a minor version bump.
- **Renames require deprecation.** If a threat or control must be renamed, keep the old ID reachable through an `aliases` field for at least one minor release before removal. (Aliases are not yet implemented — open an issue if you need one.)
- **Deletions are breaking changes** and require a major version bump plus a migration note in the changelog.
- **Wording changes to `name`, `description`, or `controls[].description` are fine** — these are not stable identifiers.

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
  "controls": [
    { "id": "ctrl-shortname-1", "description": "Actionable mitigation." }
  ]
}
```

Conventions:

- `id`: kebab-case, descriptive, 2–5 words. Use existing IDs as a guide.
- `controls[].id`: `ctrl-{threat-shortname}-{number}`, numbered sequentially within the threat.
- `severity`: judge based on typical blast radius if the threat is realised without compensating controls. Don't anchor to best-case or worst-case.
- `stride`: list every applicable category, in the canonical order from `schema.ts`.
- `mitreTechniques`: include all directly relevant techniques. Tactic strings match the ATT&CK Enterprise matrix.
- `controls`: prefer concrete, verifiable controls. Avoid generic phrases like "improve security".

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
