// Schema for the open threat database.
// These types describe pure threat taxonomy only. Anything that exists only
// as a modelling construct or rendering choice in a particular consumer —
// how threats are grouped in a UI, applied to specific elements of a
// diagram, or mitigated by tool-specific configuration — belongs in that
// consumer, not here.

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
  /**
   * Former IDs that still resolve to this control. Used when a control is
   * renamed without breaking consumers that have the old ID stored.
   */
  aliases?: string[];
}

export interface Threat {
  id: string;
  name: string;
  description: string;
  severity: ThreatSeverity;
  stride: StrideCategory[];
  mitreTechniques: MitreTechnique[];
  /**
   * Common Weakness Enumeration IDs (e.g. ['CWE-89']) for SAST/DAST
   * integration and cross-referencing with standard vulnerability catalogues.
   */
  cwes?: string[];
  controls: Control[];
  /**
   * URLs pointing to authoritative guidance: OWASP cheat sheets, NIST
   * publications, vendor security docs, RFCs.
   */
  references?: string[];
  /**
   * Former IDs that still resolve to this threat. Used when a threat is
   * renamed without breaking consumers that have the old ID stored.
   */
  aliases?: string[];
}

export interface ThreatDatabase {
  threats: Threat[];
}
