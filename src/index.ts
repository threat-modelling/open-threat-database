import threatsData from './threats.json';
import type { Threat, ThreatDatabase } from './schema';

const db = threatsData as ThreatDatabase;

export const threats: readonly Threat[] = db.threats;

const threatsById: ReadonlyMap<string, Threat> = new Map(
  db.threats.map(t => [t.id, t]),
);

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
