// Schema for the open threat database.
// These types describe pure threat taxonomy only — no consumer-specific
// concepts (connections, zones, pathway mitigations, etc.) belong here.

export type StrideCategory =
  | 'spoofing'
  | 'tampering'
  | 'repudiation'
  | 'information-disclosure'
  | 'denial-of-service'
  | 'elevation-of-privilege';

export type ThreatSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
}

export interface Control {
  id: string;
  description: string;
}

export interface Threat {
  id: string;
  name: string;
  description: string;
  severity: ThreatSeverity;
  stride: StrideCategory[];
  mitreTechniques: MitreTechnique[];
  controls: Control[];
}

export interface ThreatDatabase {
  threats: Threat[];
}
