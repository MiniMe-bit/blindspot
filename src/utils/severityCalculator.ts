import { SeverityFactors, SeverityScoreRecord } from '../types';

export const FACTOR_WEIGHTS = {
  businessImpact: 0.30,
  threatStage: 0.25,
  detectionConfidence: 0.25,
  exploitability: 0.20,
};

export const BUSINESS_IMPACT_SCORES: Record<SeverityFactors['businessImpact'], number> = {
  Low: 25,       // Isolated dev/test workload or low-tier asset
  Medium: 50,    // Departmental service or non-critical customer-facing system
  High: 75,      // Core database, production web app, or intellectual property store
  Critical: 100, // Tier-0 Domain Controller, Patient Health Records (EHR), SWIFT financial gateway
};

export const THREAT_STAGE_SCORES: Record<SeverityFactors['threatStage'], number> = {
  Reconnaissance: 20,                          // External scanning, footprinting
  'Initial Access': 40,                        // Weaponized email delivered, perimeter probe
  'Execution/Persistence': 60,                 // Script run, run keys / cron modified
  'Lateral Movement/Credential Access': 80,    // Mimikatz, LSASS dump, RDP pivoting
  'Impact/Exfiltration': 100,                  // Ransomware staging, shadow copy deletion, bulk cloud exfil
};

export const DETECTION_CONFIDENCE_SCORES: Record<SeverityFactors['detectionConfidence'], number> = {
  Low: 30,       // High false-positive rate, heuristic or speculative regex
  Medium: 60,    // Good telemetry with moderate noise, needs manual validation
  High: 85,      // High-fidelity behavioral telemetry (e.g., LSASS handle open)
  Critical: 100, // Deterministic signature / verified command injection payload
};

export const EXPLOITABILITY_SCORES: Record<SeverityFactors['exploitability'], number> = {
  Low: 25,       // Theoretical vector, requires complex chained local conditions
  Medium: 50,    // Proof of Concept published, authentication required
  High: 80,      // Unauthenticated remote exploit actively circulating
  Critical: 100, // Known Exploited Vulnerability (CISA KEV), automated wormable exploit
};

export function calculateSeverityScore(factors: SeverityFactors): {
  compositeScore: number;
  severityLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  factorBreakdown: {
    businessImpactPoints: number;
    threatStagePoints: number;
    detectionConfidencePoints: number;
    exploitabilityPoints: number;
  };
} {
  const impactRaw = BUSINESS_IMPACT_SCORES[factors.businessImpact];
  const stageRaw = THREAT_STAGE_SCORES[factors.threatStage];
  const confRaw = DETECTION_CONFIDENCE_SCORES[factors.detectionConfidence];
  const expRaw = EXPLOITABILITY_SCORES[factors.exploitability];

  const businessImpactPoints = Math.round(impactRaw * FACTOR_WEIGHTS.businessImpact * 10) / 10;
  const threatStagePoints = Math.round(stageRaw * FACTOR_WEIGHTS.threatStage * 10) / 10;
  const detectionConfidencePoints = Math.round(confRaw * FACTOR_WEIGHTS.detectionConfidence * 10) / 10;
  const exploitabilityPoints = Math.round(expRaw * FACTOR_WEIGHTS.exploitability * 10) / 10;

  const compositeScore = Math.min(100, Math.round(businessImpactPoints + threatStagePoints + detectionConfidencePoints + exploitabilityPoints));

  let severityLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  if (compositeScore >= 85) {
    severityLevel = 'Critical';
  } else if (compositeScore >= 68) {
    severityLevel = 'High';
  } else if (compositeScore >= 45) {
    severityLevel = 'Medium';
  } else {
    severityLevel = 'Low';
  }

  return {
    compositeScore,
    severityLevel,
    factorBreakdown: {
      businessImpactPoints,
      threatStagePoints,
      detectionConfidencePoints,
      exploitabilityPoints,
    },
  };
}

export function generateSeverityRationale(
  topic: string,
  factors: SeverityFactors,
  composite: number,
  level: string
): string {
  return `Finding on "${topic}" scored ${composite}/100 (${level} Severity). Driving factors: ${factors.threatStage} progression stage coupled with ${factors.businessImpact.toLowerCase()} impact on assets. Detection confidence rated at ${factors.detectionConfidence.toLowerCase()} and threat exploitability evaluated as ${factors.exploitability.toLowerCase()}. Immediate containment recommendation based on SOC escalation matrices.`;
}
