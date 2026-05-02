# open-threat-database

An open database of cyber security threats, structured for machine consumption. Each threat carries a STRIDE classification, MITRE ATT&CK technique mappings, and a set of mitigating controls.

Intended for threat modelling tools, security review tooling, and anyone who wants a curated, versioned catalogue of common threats without reinventing the taxonomy.

## Install

```bash
npm install @threat-modelling/open-threat-database
```

## Usage

```ts
import { threats, getThreatById } from '@threat-modelling/open-threat-database';
import type { Threat } from '@threat-modelling/open-threat-database';

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

### Severity

`severity` rates the intrinsic impact of a threat being realised without compensating controls. Likelihood is intentionally not weighted, since it depends on the consuming environment. The four levels are anchored to [CVSS v3.1](https://www.first.org/cvss/v3-1/specification-document) qualitative bands:

| Level | Typical impact | CVSS band |
|-------|----------------|-----------|
| **Critical** | Privileged execution (root/admin/control-plane) or kingdom-key disclosure | ≥ 9.0 |
| **High** | Non-privileged compromise, credential theft enabling further access, or substantial authorisation bypass | 7.0–8.9 |
| **Medium** | Unauthorised data access/modification, or design weaknesses that expand blast radius of other threats | 4.0–6.9 |
| **Low** | Repudiation, low-impact disclosure, or volumetric availability impact only | 0.1–3.9 |

See [CONTRIBUTING.md](./CONTRIBUTING.md#severity-rubric) for the full rubric and tie-breakers.

### JSON Schema

A JSON Schema (draft 2020-12) describing the data is published alongside the package, for consumers in any language:

```ts
import schema from '@threat-modelling/open-threat-database/schema.json' with { type: 'json' };
```

Or resolve the file path directly: `require.resolve('@threat-modelling/open-threat-database/schema.json')`.

## Using from non-JS languages

Every tagged release attaches `threats.json` and `schema.json` as GitHub Release assets, so you can fetch them from anywhere without going through npm:

```bash
# latest release
curl -L -O https://github.com/threat-modelling/open-threat-database/releases/latest/download/threats.json
curl -L -O https://github.com/threat-modelling/open-threat-database/releases/latest/download/schema.json

# pinned version
curl -L -O https://github.com/threat-modelling/open-threat-database/releases/download/v1.0.0/threats.json
```

Validate the data against the schema with any standard JSON Schema validator (e.g. `jsonschema` in Python, `gojsonschema` in Go).

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the schema details, ID-stability rules, and how to add or modify threats.

## License

MIT
