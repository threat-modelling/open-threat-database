import threatsData from './threats.json' with { type: 'json' };
import type { Threat, ThreatDatabase } from './schema';

const db = threatsData as ThreatDatabase;

export const threats: readonly Threat[] = db.threats;

const threatsById: ReadonlyMap<string, Threat> = (() => {
  const map = new Map<string, Threat>();
  for (const t of db.threats) {
    map.set(t.id, t);
    if (t.aliases) {
      for (const alias of t.aliases) {
        map.set(alias, t);
      }
    }
  }
  return map;
})();

/**
 * Look up a threat by its current ID or any of its aliases (former IDs).
 * Returns `undefined` if no threat matches.
 */
export function getThreatById(id: string): Threat | undefined {
  return threatsById.get(id);
}

export type {
  Threat,
  ThreatDatabase,
  Control,
  MitreTechnique,
  StrideCategory,
  ThreatSeverity,
} from './schema';
