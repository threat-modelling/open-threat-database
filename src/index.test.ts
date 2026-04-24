import { describe, it, expect } from 'vitest';
import { threats, getThreatById } from './index';
import type { StrideCategory, ThreatSeverity } from './schema';

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
});
