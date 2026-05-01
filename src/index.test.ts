import { describe, it, expect } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import { threats, getThreatById } from './index';
import type { StrideCategory, ThreatSeverity } from './schema';
import schemaJson from './schema.json';
import threatsJson from './threats.json';

const VALID_STRIDE: ReadonlySet<StrideCategory> = new Set([
  'spoofing',
  'tampering',
  'repudiation',
  'information-disclosure',
  'denial-of-service',
  'elevation-of-privilege',
]);

const VALID_SEVERITY: ReadonlySet<ThreatSeverity> = new Set([
  'low',
  'medium',
  'high',
  'critical',
]);

describe('threats dataset', () => {
  it('exports at least one threat', () => {
    expect(threats.length).toBeGreaterThan(0);
  });

  it('every threat has required fields', () => {
    for (const t of threats) {
      expect(t.id, `missing id`).toBeTruthy();
      expect(t.name, `${t.id} missing name`).toBeTruthy();
      expect(t.description, `${t.id} missing description`).toBeTruthy();
      expect(t.stride.length, `${t.id} has empty stride[]`).toBeGreaterThan(0);
      expect(Array.isArray(t.mitreTechniques)).toBe(true);
      expect(Array.isArray(t.controls)).toBe(true);
    }
  });

  it('threat IDs are unique', () => {
    const seen = new Set<string>();
    const dupes: string[] = [];
    for (const t of threats) {
      if (seen.has(t.id)) dupes.push(t.id);
      seen.add(t.id);
    }
    expect(dupes, `duplicate threat IDs: ${dupes.join(', ')}`).toEqual([]);
  });

  it('control IDs are unique across all threats', () => {
    const seen = new Set<string>();
    const dupes: string[] = [];
    for (const t of threats) {
      for (const c of t.controls) {
        if (seen.has(c.id)) dupes.push(c.id);
        seen.add(c.id);
      }
    }
    expect(dupes, `duplicate control IDs: ${dupes.join(', ')}`).toEqual([]);
  });

  it('every stride value is from the allowed set', () => {
    for (const t of threats) {
      for (const s of t.stride) {
        expect(VALID_STRIDE.has(s), `${t.id}: invalid stride "${s}"`).toBe(true);
      }
    }
  });

  it('every severity is from the allowed set', () => {
    for (const t of threats) {
      expect(VALID_SEVERITY.has(t.severity), `${t.id}: invalid severity "${t.severity}"`).toBe(true);
    }
  });
});

describe('getThreatById', () => {
  it('returns the threat when found', () => {
    const first = threats[0];
    expect(getThreatById(first.id)).toBe(first);
  });

  it('returns undefined for unknown ids', () => {
    expect(getThreatById('does-not-exist')).toBeUndefined();
  });

  it('resolves aliases to the current threat', () => {
    for (const t of threats) {
      if (!t.aliases) continue;
      for (const alias of t.aliases) {
        expect(getThreatById(alias), `alias ${alias} should resolve to ${t.id}`).toBe(t);
      }
    }
  });
});

describe('aliases', () => {
  it('no threat alias collides with a primary threat id', () => {
    const primaryIds = new Set(threats.map(t => t.id));
    const collisions: string[] = [];
    for (const t of threats) {
      for (const alias of t.aliases ?? []) {
        if (primaryIds.has(alias)) {
          collisions.push(`${alias} (alias on ${t.id})`);
        }
      }
    }
    expect(collisions, `alias collides with primary id: ${collisions.join(', ')}`).toEqual([]);
  });

  it('no threat alias is reused across threats', () => {
    const seen = new Map<string, string>();
    const dupes: string[] = [];
    for (const t of threats) {
      for (const alias of t.aliases ?? []) {
        const owner = seen.get(alias);
        if (owner) {
          dupes.push(`${alias} (on ${owner} and ${t.id})`);
        } else {
          seen.set(alias, t.id);
        }
      }
    }
    expect(dupes, `duplicate aliases: ${dupes.join(', ')}`).toEqual([]);
  });

  it('no control alias collides with a primary control id', () => {
    const primaryIds = new Set<string>();
    for (const t of threats) {
      for (const c of t.controls) primaryIds.add(c.id);
    }
    const collisions: string[] = [];
    for (const t of threats) {
      for (const c of t.controls) {
        for (const alias of c.aliases ?? []) {
          if (primaryIds.has(alias)) {
            collisions.push(`${alias} (alias on ${c.id})`);
          }
        }
      }
    }
    expect(collisions, `control alias collides with primary id: ${collisions.join(', ')}`).toEqual([]);
  });

  it('no control alias is reused across controls', () => {
    const seen = new Map<string, string>();
    const dupes: string[] = [];
    for (const t of threats) {
      for (const c of t.controls) {
        for (const alias of c.aliases ?? []) {
          const owner = seen.get(alias);
          if (owner) {
            dupes.push(`${alias} (on ${owner} and ${c.id})`);
          } else {
            seen.set(alias, c.id);
          }
        }
      }
    }
    expect(dupes, `duplicate control aliases: ${dupes.join(', ')}`).toEqual([]);
  });
});

describe('JSON Schema', () => {
  it('threats.json validates against schema.json', () => {
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    const validate = ajv.compile(schemaJson);
    const ok = validate(threatsJson);
    if (!ok) {
      const formatted = (validate.errors ?? [])
        .map(e => `${e.instancePath} ${e.message}`)
        .join('\n');
      throw new Error(`threats.json failed schema validation:\n${formatted}`);
    }
    expect(ok).toBe(true);
  });
});
