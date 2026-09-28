import type { ReportDraft } from '../types';
import { MITRE_TECHNIQUES } from '../data/mitreAttck';

/** Build a report draft from a single ATT&CK technique, using its catalog description and sample query. */
export function draftFromTechnique(techniqueId: string): ReportDraft {
  const tech = MITRE_TECHNIQUES.find((t) => t.id === techniqueId);
  if (!tech) return { hypothesisTitle: '', techniqueIds: [techniqueId] };
  return {
    hypothesisTitle: `${tech.name} (${tech.id})`,
    hypothesisDescription: tech.description,
    techniqueIds: [tech.id],
    dataSources: tech.dataSources,
    queryLanguage: tech.sampleQuery?.language,
    queryText: tech.sampleQuery?.query,
  };
}
