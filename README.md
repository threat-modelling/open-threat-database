# open-threat-database

An open database of cyber security threats, structured for machine consumption. Each threat carries a STRIDE classification, MITRE ATT&CK technique mappings, and a set of mitigating controls.

Intended for threat modelling tools, security review tooling, and anyone who wants a curated, versioned catalogue of common threats without reinventing the taxonomy.

## Install

```bash
npm install open-threat-database
```

## Usage

```ts
import { threats, getThreatById } from 'open-threat-database';
import type { Threat } from 'open-threat-database';

console.log(threats.length);

const sqli = getThreatById('sql-injection');
console.log(sqli?.controls.map(c => c.description));
```

## Schema

A `Threat` is:

```ts
interface Threat {
  id: string;                       // permanent, kebab-case identifier
  name: string;                     // human-readable title
  description: string;              // one-paragraph summary
  severity: 'low' | 'medium' | 'high' | 'critical';
  stride: StrideCategory[];         // one or more STRIDE categories
  mitreTechniques: MitreTechnique[];
  cwes?: string[];                  // CWE IDs, e.g. ['CWE-89'] for SAST/DAST integration
  controls: Control[];
  references?: string[];            // URLs to OWASP, NIST, vendor docs, RFCs
  aliases?: string[];               // former IDs that still resolve to this threat
}
```

See `src/schema.ts` for the full type definitions.

### JSON Schema

A JSON Schema (draft 2020-12) describing the data is published alongside the package, for consumers in any language:

```ts
import schema from 'open-threat-database/schema.json' with { type: 'json' };
```

Or resolve the file path directly: `require.resolve('open-threat-database/schema.json')`.

## Using from non-JS languages

Every tagged release attaches `threats.json` and `schema.json` as GitHub Release assets, so you can fetch them from anywhere without going through npm:

```bash
# latest release
curl -L -O https://github.com/jib1337/open-threat-database/releases/latest/download/threats.json
curl -L -O https://github.com/jib1337/open-threat-database/releases/latest/download/schema.json

# pinned version
curl -L -O https://github.com/jib1337/open-threat-database/releases/download/v1.0.0/threats.json
```

Validate the data against the schema with any standard JSON Schema validator (e.g. `jsonschema` in Python, `gojsonschema` in Go).

### Stable identifiers and aliases

`id` values on threats and controls are permanent. If a threat is renamed, the old ID is preserved in `aliases` and `getThreatById('old-id')` continues to return the renamed threat. See [CONTRIBUTING.md](./CONTRIBUTING.md#the-id-stability-contract) for the full contract.

## Releasing

### Cutting a release

1. Bump `version` in `package.json` according to the semver policy in [CONTRIBUTING.md](./CONTRIBUTING.md#releasing).
2. Commit the bump.
3. Tag and push:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

4. *(Optional)* Publish to npm from the same commit:

   ```bash
   npm publish
   ```

   The release workflow handles GitHub Releases only — it does not run `npm publish`. If you want the package on npm too, that step is manual (or wire it into the workflow).

### The release workflow

`.github/workflows/release.yml` runs on any pushed tag matching `v*`. It:

1. Checks out the tag.
2. Sets up Node 20 with an npm cache.
3. Runs `npm ci`.
4. Runs `npm test` — alias collision, schema validation, and ID uniqueness checks all gate the release. A failure here blocks publication.
5. Runs `npm run build` to produce `dist/index.js`, `dist/threats.json`, and `dist/schema.json`.
6. Creates a GitHub Release for the tag using `gh release create --generate-notes`, attaching `threats.json` and `schema.json` as release assets. The notes are auto-generated from commits since the previous tag.

If a release fails after the tag is pushed, fix the underlying issue on the branch, delete the tag locally and remotely (`git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z`), and re-tag.

The workflow only needs `contents: write` permission and uses the built-in `GITHUB_TOKEN` — no extra secrets to configure.

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

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the schema details, ID-stability rules, and how to add or modify threats.

## License

MIT
