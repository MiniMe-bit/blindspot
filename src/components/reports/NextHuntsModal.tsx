import React, { useEffect, useState } from 'react';
import { Info, Lightbulb } from 'lucide-react';
import type { NextHuntRecommendation } from '../../types';
import { useApp } from '../../app/AppContext';
import { MITRE_TECHNIQUES } from '../../data/mitreAttck';
import { fetchNextHuntRecommendations } from '../../services/api';
import { coveredTechniqueSet } from '../../lib/coverage';
import { Badge, Button, EmptyState, Modal, severityTone } from '../ui';

/** Suggests uncovered techniques to hunt next. Fetched on open, not on every page visit. */
export const NextHuntsModal: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const { currentClient, clientReports, startReport } = useApp();
  const [recs, setRecs] = useState<NextHuntRecommendation[]>([]);
  const [fallback, setFallback] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const covered = Array.from(coveredTechniqueSet(clientReports));
    const uncovered = MITRE_TECHNIQUES.filter((t) => !covered.includes(t.id)).map((t) => `${t.id} - ${t.name}`);
    fetchNextHuntRecommendations(currentClient, covered, uncovered)
      .then((res) => {
        if (cancelled) return;
        setRecs(res.data);
        setFallback(res.fallback);
      })
      .catch(() => !cancelled && setError('Could not load suggestions. Check the server connection.'))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
    // Fetch once per open.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <Modal open onClose={onClose} size="lg" title="Suggested next hunts" description={`Uncovered techniques weighted for ${currentClient.industry} threats.`}>
      {loading ? (
        <div className="space-y-3">
          {[0, 1, 2].map((i) => (
            <div key={i} className="h-28 animate-pulse rounded-md bg-surface-2" />
          ))}
        </div>
      ) : error ? (
        <EmptyState icon={Info} title="Suggestions unavailable" description={error} />
      ) : recs.length === 0 ? (
        <EmptyState icon={Lightbulb} title="No suggestions" description="Nothing to suggest right now." />
      ) : (
        <div className="space-y-3">
          {fallback && (
            <div className="flex items-start gap-2 rounded-md border border-border bg-surface-2 px-3 py-2.5 text-[13px] text-fg-muted">
              <Info className="mt-0.5 size-4 shrink-0 text-accent" />
              AI service unavailable — showing curated suggestions for this sector, not an analysis of this client's reports.
            </div>
          )}
          {recs.map((r) => (
            <div key={r.techniqueId} className="rounded-md border border-border p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-xs text-fg-subtle">
                    <span className="font-mono">{r.techniqueId}</span> · {r.tactic}
                  </div>
                  <div className="mt-0.5 text-sm font-medium text-fg">{r.techniqueName}</div>
                </div>
                <Badge tone={severityTone(r.priority)}>{r.priority}</Badge>
              </div>
              <p className="mt-2 text-[13px] leading-relaxed text-fg-muted">{r.whyThisTechnique}</p>
              {r.threatActorContext && <p className="mt-1.5 text-xs text-fg-subtle">{r.threatActorContext}</p>}
              <div className="mt-3 flex items-center justify-between gap-3">
                <span className="truncate text-xs text-fg-subtle">Needs: {r.requiredDataSources.join(', ')}</span>
                <Button
                  size="sm"
                  variant="primary"
                  onClick={() => {
                    const tech = MITRE_TECHNIQUES.find((t) => t.id === r.techniqueId);
                    onClose();
                    startReport({
                      hypothesisTitle: `${r.techniqueName} (${r.techniqueId})`,
                      hypothesisDescription: r.suggestedHypothesis,
                      techniqueIds: [r.techniqueId],
                      dataSources: r.requiredDataSources,
                      queryLanguage: tech?.sampleQuery?.language,
                      queryText: tech?.sampleQuery?.query,
                    });
                  }}
                >
                  Start report
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
    </Modal>
  );
};
