export type UserRole = 'analyst' | 'lead' | 'admin';

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  orgId: string;
  avatar?: string;
  huntCount: number;
}

export type IndustryVertical = 
  | 'healthcare'
  | 'finance'
  | 'defense'
  | 'retail'
  | 'technology'
  | 'energy';

export interface ClientOrg {
  id: string;
  name: string;
  industry: IndustryVertical;
  description: string;
  /** Bundled brand logo (see src/data/clientLogos.ts). */
  logoSlug?: string;
  /** Optional logo image URL, used when there is no bundled logo. */
  logoUrl?: string;
  primaryTelemetry: string[];
  threatProfile: {
    primaryAdversaries: string[];
    topTargetedAssets: string[];
    complianceFrameworks: string[];
    riskTolerance: 'Low' | 'Moderate' | 'Aggressive';
  };
}

export type MitreTactic = 
  | 'Reconnaissance'
  | 'Resource Development'
  | 'Initial Access'
  | 'Execution'
  | 'Persistence'
  | 'Privilege Escalation'
  | 'Defense Evasion'
  | 'Credential Access'
  | 'Discovery'
  | 'Lateral Movement'
  | 'Collection'
  | 'Command and Control'
  | 'Exfiltration'
  | 'Impact';

export interface MitreTechnique {
  id: string; // e.g., "T1059"
  name: string;
  tactic: MitreTactic;
  tacticId: string; // e.g., "TA0002"
  description: string;
  subTechniques?: Array<{
    id: string; // e.g. "T1059.001"
    name: string;
    description: string;
  }>;
  dataSources: string[];
  platforms: string[];
  sampleQuery?: {
    language: 'KQL' | 'SPL' | 'Sigma' | 'EQL';
    query: string;
  };
}

export type HuntOutcome = 'True Positive' | 'False Positive' | 'No Result' | 'Needs Follow-up';

export interface IOC {
  id: string;
  type: 'IP' | 'Domain' | 'Hash' | 'Process' | 'Registry' | 'Account';
  value: string;
  notes?: string;
}

export interface SeverityFactors {
  businessImpact: 'Low' | 'Medium' | 'High' | 'Critical';
  threatStage: 'Reconnaissance' | 'Initial Access' | 'Execution/Persistence' | 'Lateral Movement/Credential Access' | 'Impact/Exfiltration';
  detectionConfidence: 'Low' | 'Medium' | 'High' | 'Critical';
  exploitability: 'Low' | 'Medium' | 'High' | 'Critical';
}

export interface SeverityScoreRecord {
  id: string;
  huntReportId?: string;
  clientId: string;
  topic: string;
  summary: string;
  query: string;
  factors: SeverityFactors;
  compositeScore: number; // 0 - 100
  severityLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  factorBreakdown: {
    businessImpactPoints: number;
    threatStagePoints: number;
    detectionConfidencePoints: number;
    exploitabilityPoints: number;
  };
  rationale?: string;
  createdAt: string;
}

export interface ThreatHuntQueryItem {
  id: string;
  platform: 'KQL' | 'SPL' | 'Sigma' | 'EQL' | 'CrowdStrike (FQL)' | 'SentinelOne (S1QL)' | 'Trend Micro Vision One' | 'Other';
  title?: string;
  code: string;
  explanation?: string;
}

export interface ThreatHuntReportDocument {
  hypothesisName: string; // <Hypothesis Name>
  reportDate: string; // Date of hunt
  executiveSummary: string;
  purpose: string;
  mitreInformation: string;
  huntMethodology: string;
  potentialDetectionIdeas: string;
  huntQueries: ThreatHuntQueryItem[];
  huntResults: string;
  analysis: string;
  risk: string;
  impact: string;
  recommendation: string;
  references: string[];
}

export interface HuntReport {
  id: string;
  clientId: string;
  analystId: string;
  analystName: string;
  weekRange: string; // e.g., "2026-W38 (Sep 14 - Sep 20)"
  hypothesisTitle: string;
  hypothesisDescription: string;
  techniqueIds: string[]; // MITRE IDs e.g. ["T1059.001", "T1078"]
  dataSources: string[];
  queryLanguage: 'KQL' | 'SPL' | 'Sigma' | 'EQL';
  queryText: string;
  outcome: HuntOutcome;
  notes: string;
  iocs: IOC[];
  severityScore?: SeverityScoreRecord;
  createdAt: string;
  updatedAt?: string;
  isTHR?: boolean;
  /** Hunt phase (10 hunts per phase). Older records may not have one. */
  phase?: number;
  reportDate?: string;
  thrDocument?: ThreatHuntReportDocument;
}

export type TodayHuntSource =
  | 'CVE / CISA KEV'
  | 'Ransomware'
  | 'APT'
  | 'Malware'
  | 'ClickFix'
  | 'Threat Actor Intel'
  | 'Coverage Gap';

/** Query platforms hunters can pull a hunt's query for. */
export type HuntPlatform = 'crowdstrike' | 'defender' | 'trendmicro' | 'elastic' | 'sigma' | 'splunk';

export interface HuntReference {
  title: string;
  url: string;
  publisher?: string;
  /** Added by a hunter in this workspace (vs. shipped with the hunt). */
  addedBy?: string;
  /** Suggested by the AI generator; the link has not been checked. */
  unverified?: boolean;
}

export interface AIHuntScoreBreakdown {
  threatRelevance: number; // 0 - 100%
  telemetryAvailable: number; // 0 - 100%
  detectionGap: number; // 0 - 100%
  recentActivity: number; // 0 - 100%
  historicalPrevalence: number; // 0 - 100%
  priorityScore: number; // Weighted composite 0 - 100
}

export interface TodayHunt {
  id: string;
  clientId: string;
  source: TodayHuntSource;
  sourceReference: string; // e.g. "CVE-2024-38112" or "Akira Ransomware Alert"
  priority: 'Critical' | 'High' | 'Medium' | 'Low';
  hypothesisName: string;
  techniques: Array<{
    id: string;
    name: string;
    tactic: MitreTactic;
  }>;
  dataSourcesRequired: string[];
  summaryAndRationale: string;
  suggestedQuery: {
    language: 'KQL' | 'SPL' | 'Sigma';
    code: string;
  };
  /** Equivalent hunting query per platform. Missing platforms have no query yet. */
  platformQueries?: Partial<Record<HuntPlatform, string>>;
  /** Blogs and advisories for background reading. */
  references?: HuntReference[];
  expectedBaseline: string; // What normal looks like
  truePositiveExample: string; // Log pattern indicating true positive
  aiHuntScore: AIHuntScoreBreakdown;
  generatedAt: string;
  isDrafted?: boolean;
  status?: TodayHuntStatus;
}

export type TodayHuntStatus = 'queued' | 'in-progress' | 'done';

/** One row of a hunter's daily threat intel IOC / CVE-check hunting sheet. */
export interface IocHunt {
  id: string;
  clientId: string;
  /** The sheet's own row number / reference, as written by the hunter. */
  number: string;
  title: string;
  description: string;
  /** Malware, ClickFix, Ransomware, CVE, Stealer, APT, ... (free text from the sheet, normalised). */
  category: string;
  queryCount: number;
  /** What the queries found, e.g. "No hits" or "2 hosts matched". */
  results: string;
  /** Escalation reference: task ID / ServiceNow ID. Empty when not escalated. */
  escalation: string;
  queries: string;
  date?: string;
  origin: 'demo' | 'upload';
  importedAt: string;
}

/** Prefill passed to the hunt report form when starting a report from another page. */
export interface ReportDraft {
  hypothesisTitle: string;
  hypothesisDescription?: string;
  techniqueIds: string[];
  dataSources?: string[];
  queryLanguage?: HuntReport['queryLanguage'];
  queryText?: string;
  notes?: string;
}

/** Payload for creating a detection rule from a hunt, intel item, or coverage gap. */
export interface RuleDraft {
  ruleName: string;
  queryLogic: string;
  techniqueIds: string[];
  tactics: string[];
  platform: DetectionPlatform;
  description: string;
  huntReportId?: string;
}

export interface NextHuntRecommendation {
  id: string;
  techniqueId: string;
  techniqueName: string;
  tactic: MitreTactic;
  priority: 'Critical' | 'High' | 'Medium' | 'Low';
  whyThisTechnique: string;
  requiredDataSources: string[];
  suggestedHypothesis: string;
  subTechniquesCovered: string[];
  subTechniquesUncovered: string[];
  threatActorContext?: string;
}

export interface DeckSlide {
  id: string;
  title: string;
  subtitle: string;
  type: 
    | 'title'
    | 'executive_summary'
    | 'kpi_performance'
    | 'ioc_hunting'
    | 'mitre_coverage_heatmap'
    | 'severity_distribution'
    | 'key_findings'
    | 'blind_spots'
    | 'strategic_roadmap';
  content: Record<string, any>;
}

export interface GeneratedDeck {
  id: string;
  clientId: string;
  clientName: string;
  industry: string;
  periodType: 'monthly' | 'quarterly' | 'custom';
  periodLabel: string; // e.g. "Q3 2026 Executive Hunting Report"
  dateRange: string;
  generatedAt: string;
  generatedBy: string;
  narrativeSummary: string;
  slides: DeckSlide[];
}

export type DetectionRuleStatus = 
  | 'Production Active' 
  | 'Testing / Staging' 
  | 'Pending Client Review' 
  | 'Tuning Needed' 
  | 'Deprecated';

export type DetectionPlatform = 
  | 'Microsoft Sentinel (KQL)' 
  | 'Splunk Enterprise (SPL)' 
  | 'CrowdStrike Falcon (LQL)' 
  | 'SentinelOne (Deep Visibility)'
  | 'Trend Micro Vision One'
  | 'Sigma (Generic)' 
  | 'Elasticsearch (EQL)';

export interface DetectionRule {
  id: string;
  clientId: string;
  huntReportId?: string; // Origin hunt report if promoted from a hunt
  huntHypothesisTitle: string;
  ruleName: string;
  description: string;
  platform: DetectionPlatform;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  status: DetectionRuleStatus;
  techniqueIds: string[];
  tactics: string[];
  queryLogic: string;
  targetDataSources: string[];
  targetEnvironment: string; // e.g. "Prod Sentinel: ws-sec-ops-01" or "Splunk Enterprise ES: Cluster-US-East"
  deployedBy: string;
  sentDate: string;
  approvedDate?: string;
  lastTriggeredDate?: string;
  totalAlertsTriggered: number;
  falsePositiveRatePct: number;
  tuningNotes?: string;
  clientApprover?: string;
  runbookUrl?: string;
}

export interface SectorThreatIntel {
  id: string;
  title: string;
  sectors: string[]; // e.g. ['healthcare', 'retail', 'finance', 'defense', 'energy', 'technology']
  targetedCountries: string[]; // e.g. ['United States', 'United Kingdom', 'Germany', 'Australia', 'Canada']
  threatActors: string[]; // e.g. ['Clop Ransomware', 'Qilin Ransomware', 'Scattered Spider', 'Akira Ransomware']
  cvesObserved?: string[]; // e.g. ['CVE-2024-55956 (Cleo RCE)', 'CVE-2024-55591 (FortiOS)']
  summary: string;
  urgency: 'Critical' | 'High' | 'Medium';
  entryVectors: string[]; // e.g. ['Zero-Day Edge Exploitation', 'Helpdesk Vishing / SIM Swap', 'MFA Fatigue']
  primaryTTPs: Array<{
    id: string;
    name: string;
    tactic: MitreTactic;
  }>;
  suggestedHuntPackage: {
    hypothesisTitle: string;
    description: string;
    queryLanguage: 'KQL' | 'SPL' | 'Sigma';
    queryCode: string;
    requiredDataSources: string[];
    logPattern: string;
    platformQueries?: {
      sigma?: string;
      fql?: string; // CrowdStrike Falcon Query Language
      kql?: string; // Microsoft Sentinel
      sentinelone?: string; // SentinelOne Deep Visibility / S1QL
      trendmicro?: string; // Trend Micro Vision One
      splunk?: string; // Splunk SPL
      elastic?: string; // Elastic EQL / ES|QL
    };
  };
  publishedDate: string;
  sourceAttribution: string; // e.g. "BleepingComputer • CISA KEV Alert", "The Hacker News • Threat Advisory"
  sourcePublisher?: 'BleepingComputer' | 'The Hacker News' | 'SecurePoint' | 'CISA KEV' | string;
  sourceUrl?: string;
}
