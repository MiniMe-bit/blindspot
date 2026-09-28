import { AIHuntScoreBreakdown, ClientOrg, HuntReport } from '../types';

export interface ScoreWeights {
  threatRelevance: number;
  telemetryAvailable: number;
  detectionGap: number;
  recentActivity: number;
  historicalPrevalence: number;
}

export const DEFAULT_HUNT_SCORE_WEIGHTS: ScoreWeights = {
  threatRelevance: 0.25,
  telemetryAvailable: 0.20,
  detectionGap: 0.25,
  recentActivity: 0.15,
  historicalPrevalence: 0.15,
};

export function computeTechniqueGapAndRecency(
  techniqueId: string,
  clientReports: HuntReport[]
): { detectionGap: number; recentActivity: number; historicalPrevalence: number } {
  const huntsOnTechnique = clientReports.filter(r => 
    r.techniqueIds.includes(techniqueId) || r.techniqueIds.some(t => t.startsWith(techniqueId))
  );

  // If never hunted, detection gap is 100%
  let detectionGap = 100;
  if (huntsOnTechnique.length >= 4) {
    detectionGap = 15;
  } else if (huntsOnTechnique.length === 3) {
    detectionGap = 35;
  } else if (huntsOnTechnique.length === 2) {
    detectionGap = 55;
  } else if (huntsOnTechnique.length === 1) {
    detectionGap = 75;
  }

  // Recent Hunt Activity (inverse recency: less recently hunted = higher score for hunting priority)
  let recentActivity = 95; // never hunted
  if (huntsOnTechnique.length > 0) {
    // Check days since last hunt
    const sorted = [...huntsOnTechnique].sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
    const lastDate = new Date(sorted[0].createdAt);
    const now = new Date();
    const diffDays = Math.max(1, Math.floor((now.getTime() - lastDate.getTime()) / (1000 * 60 * 60 * 24)));

    if (diffDays <= 7) {
      recentActivity = 20; // Hunted just this week, lower urgency to repeat immediately
    } else if (diffDays <= 21) {
      recentActivity = 45;
    } else if (diffDays <= 45) {
      recentActivity = 70;
    } else {
      recentActivity = 90; // Over a month ago, high need to re-verify
    }
  }

  // Historical Prevalence (how often technique shows up as True Positive)
  const tpCount = huntsOnTechnique.filter(r => r.outcome === 'True Positive').length;
  let historicalPrevalence = 40; // baseline industry expectation
  if (huntsOnTechnique.length > 0) {
    const tpRatio = tpCount / huntsOnTechnique.length;
    historicalPrevalence = Math.round(tpRatio * 80 + 20);
  } else {
    // Common high-frequency techniques get elevated baseline
    if (['T1059', 'T1078', 'T1003', 'T1190', 'T1566'].includes(techniqueId)) {
      historicalPrevalence = 85;
    } else {
      historicalPrevalence = 50;
    }
  }

  return { detectionGap, recentActivity, historicalPrevalence };
}

export function computeTelemetryAvailability(
  requiredDataSources: string[],
  client: ClientOrg
): number {
  if (!requiredDataSources || requiredDataSources.length === 0) return 90;
  
  const clientTelemetry = client.primaryTelemetry.map(t => t.toLowerCase());
  let matched = 0;
  
  for (const req of requiredDataSources) {
    const reqLower = req.toLowerCase();
    const hasMatch = clientTelemetry.some(t => 
      t.includes(reqLower) || reqLower.includes(t) ||
      (reqLower.includes('edr') && t.includes('edr')) ||
      (reqLower.includes('dns') && t.includes('dns')) ||
      (reqLower.includes('proxy') && t.includes('proxy')) ||
      (reqLower.includes('cloud') && (t.includes('cloud') || t.includes('aws') || t.includes('azure'))) ||
      (reqLower.includes('sysmon') && (t.includes('sysmon') || t.includes('windows'))) ||
      (reqLower.includes('okta') && (t.includes('okta') || t.includes('identity')))
    );
    if (hasMatch) matched++;
  }

  const coverageRatio = matched / requiredDataSources.length;
  return Math.round(coverageRatio * 100);
}

export function computeAIHuntScore(
  techniqueId: string,
  requiredDataSources: string[],
  client: ClientOrg,
  clientReports: HuntReport[],
  sourceType: string,
  customWeights: ScoreWeights = DEFAULT_HUNT_SCORE_WEIGHTS
): AIHuntScoreBreakdown {
  const { detectionGap, recentActivity, historicalPrevalence } = computeTechniqueGapAndRecency(techniqueId, clientReports);
  const telemetryAvailable = computeTelemetryAvailability(requiredDataSources, client);

  // Threat relevance: boosted if active CVE or ransomware campaign or client's specific industry
  let threatRelevance = 65;
  if (sourceType.includes('CVE') || sourceType.includes('KEV')) {
    threatRelevance = 95;
  } else if (sourceType.includes('Ransomware')) {
    threatRelevance = 92;
  } else if (sourceType.includes('Threat Actor')) {
    threatRelevance = 88;
  } else if (client.industry === 'healthcare' && ['T1486', 'T1566', 'T1078', 'T1003'].includes(techniqueId)) {
    threatRelevance = 94;
  } else if (client.industry === 'finance' && ['T1078', 'T1110', 'T1567', 'T1021'].includes(techniqueId)) {
    threatRelevance = 92;
  } else if (client.industry === 'defense' && ['T1190', 'T1059', 'T1055', 'T1071'].includes(techniqueId)) {
    threatRelevance = 96;
  }

  const priorityScore = Math.min(100, Math.round(
    threatRelevance * customWeights.threatRelevance +
    telemetryAvailable * customWeights.telemetryAvailable +
    detectionGap * customWeights.detectionGap +
    recentActivity * customWeights.recentActivity +
    historicalPrevalence * customWeights.historicalPrevalence
  ));

  return {
    threatRelevance,
    telemetryAvailable,
    detectionGap,
    recentActivity,
    historicalPrevalence,
    priorityScore,
  };
}
