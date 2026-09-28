import type { ClientOrg, HuntPlatform, TodayHunt, TodayHuntSource } from '../types';

export interface PlatformDef {
  id: HuntPlatform;
  /** Product name shown on the platform bar. */
  label: string;
  /** Query language shown under the label and on the code block. */
  language: string;
  /** Loose match against a client's onboarded telemetry, to preselect their platform. */
  telemetryHints: string[];
}

export const PLATFORMS: PlatformDef[] = [
  { id: 'crowdstrike', label: 'CrowdStrike Falcon', language: 'FQL', telemetryHints: ['crowdstrike', 'falcon'] },
  { id: 'defender', label: 'Microsoft Defender', language: 'KQL', telemetryHints: ['defender', 'sentinel'] },
  { id: 'trendmicro', label: 'Trend Micro Vision One', language: 'Vision One search', telemetryHints: ['trend micro', 'vision one'] },
  { id: 'elastic', label: 'Elastic', language: 'EQL', telemetryHints: ['elastic'] },
  { id: 'sigma', label: 'Sigma', language: 'Sigma YAML', telemetryHints: [] },
  { id: 'splunk', label: 'Splunk', language: 'SPL', telemetryHints: ['splunk'] },
];

export const platformDef = (id: HuntPlatform) => PLATFORMS.find((p) => p.id === id)!;

/** The platform matching the client's onboarded EDR/SIEM, or Sigma (portable) when nothing matches. */
export function defaultPlatformFor(client: ClientOrg): HuntPlatform {
  const telemetry = client.primaryTelemetry.join(' ').toLowerCase();
  return PLATFORMS.find((p) => p.telemetryHints.some((h) => telemetry.includes(h)))?.id ?? 'sigma';
}

/** Legacy single-query field, mapped onto the platform it was written for. */
const LEGACY_LANGUAGE: Record<TodayHunt['suggestedQuery']['language'], HuntPlatform> = {
  KQL: 'defender',
  SPL: 'splunk',
  Sigma: 'sigma',
};

/** The hunt's query for a platform, or undefined when none has been written for it. */
export function queryFor(hunt: TodayHunt, platform: HuntPlatform): string | undefined {
  const q = hunt.platformQueries?.[platform];
  if (q?.trim()) return q;
  if (hunt.suggestedQuery && LEGACY_LANGUAGE[hunt.suggestedQuery.language] === platform) return hunt.suggestedQuery.code;
  return undefined;
}

export type SourceTone = 'accent' | 'danger' | 'violet' | 'warning' | 'teal' | 'pink' | 'neutral';

export interface SourceDef {
  id: TodayHuntSource;
  label: string;
  help: string;
  tone: SourceTone;
}

export const SOURCES: SourceDef[] = [
  { id: 'CVE / CISA KEV', label: 'CVE', help: 'Exploited vulnerabilities, including CISA KEV entries', tone: 'accent' },
  { id: 'Ransomware', label: 'Ransomware', help: 'Ransomware operations and their pre-encryption tradecraft', tone: 'danger' },
  { id: 'APT', label: 'APT', help: 'Nation-state and advanced persistent threat activity', tone: 'violet' },
  { id: 'Malware', label: 'Malware', help: 'Loaders, infostealers, RATs and other malware families', tone: 'warning' },
  { id: 'ClickFix', label: 'ClickFix', help: 'Fake CAPTCHA / "fix it" lures that trick users into running commands', tone: 'teal' },
  { id: 'Threat Actor Intel', label: 'Threat actor', help: 'Financially motivated groups (eCrime) and their tradecraft', tone: 'pink' },
  { id: 'Coverage Gap', label: 'Coverage gap', help: 'ATT&CK techniques this client has not hunted recently', tone: 'neutral' },
];

export const sourceDef = (id: string): SourceDef => SOURCES.find((s) => s.id === id) ?? SOURCES[SOURCES.length - 1];

/** Older saved hunts used different source names. */
export const LEGACY_SOURCE: Record<string, TodayHuntSource> = {
  'Ransomware Campaign': 'Ransomware',
};
