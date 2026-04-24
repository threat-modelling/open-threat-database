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
  controls: Control[];
}
```

See `src/schema.ts` for the full type definitions.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the schema details, ID-stability rules, and how to add or modify threats.

## License

MIT
