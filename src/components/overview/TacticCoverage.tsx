import React, { useMemo, useState } from 'react';
import { ArrowRight, Check, ChevronDown, ChevronRight, ExternalLink, Users } from 'lucide-react';
import type { MitreTechnique, ReportDraft } from '../../types';
import { MITRE_TACTICS, MITRE_TECHNIQUES } from '../../data/mitreAttck';
import { groupUrl, TECHNIQUE_GUIDE, techniqueUrl } from '../../data/techniqueGuide';
import { cn } from '../../lib/cn';
import { Button, Card, CardHeader, CodeBlock, SectionLabel } from '../ui';

interface Props {
  covered: Set<string>;
  onStartHunt: (draft: ReportDraft) => void;
  onOpenCoverage: () => void;
}

/** Tactic-by-tactic coverage. Hunted techniques show in color; gaps open into a hunt guide. */
export const TacticCoverage: React.FC<Props> = ({ covered, onStartHunt, onOpenCoverage }) => {
  const tactics = useMemo(
    () =>
      MITRE_TACTICS.map((tac) => {
        const techs = MITRE_TECHNIQUES.filter((t) => t.tactic === tac.name);
        return { ...tac, techs, coveredCount: techs.filter((t) => covered.has(t.id)).length };
      }).filter((t) => t.techs.length),
    [covered],
  );
  const totalCovered = tactics.reduce((a, t) => a + t.coveredCount, 0);
  const total = tactics.reduce((a, t) => a + t.techs.length, 0);

  // Open the first tactic that has gaps, so the page immediately shows what to hunt next.
  const [open, setOpen] = useState<string | null>(() => tactics.find((t) => t.coveredCount < t.techs.length)?.id ?? null);

  return (
    <Card>
      <CardHeader
        tone="violet"
        title="Coverage by tactic"
        description={`${totalCovered} of ${total} catalog techniques hunted. Open a tactic to see what's left and how to hunt it.`}
        actions={
          <Button size="sm" variant="ghost" iconRight={ArrowRight} onClick={onOpenCoverage}>
            Full matrix
          </Button>
        }
      />
      <div className="flex flex-wrap items-center gap-4 border-b border-border px-5 py-2.5 text-xs text-fg-muted">
        <span className="flex items-center gap-1.5">
          <span className="inline-flex size-3.5 items-center justify-center rounded bg-success text-canvas">
            <Check className="size-2.5" strokeWidth={3} />
          </span>
          Hunted
        </span>
        <span className="flex items-center gap-1.5">
          <span className="size-3.5 rounded border border-dashed border-fg-subtle" /> Not hunted yet — hunt idea available
        </span>
      </div>

      <ul className="divide-y divide-border">
        {tactics.map((tac) => {
          const isOpen = open === tac.id;
          const gaps = tac.techs.filter((t) => !covered.has(t.id));
          const pct = Math.round((tac.coveredCount / tac.techs.length) * 100);
          return (
            <li key={tac.id}>
              <button
                type="button"
                onClick={() => setOpen(isOpen ? null : tac.id)}
                aria-expanded={isOpen}
                className="w-full px-5 py-3 text-left transition-colors hover:bg-surface-2"
              >
                <div className="flex items-center gap-3">
                  {isOpen ? <ChevronDown className="size-4 shrink-0 text-fg-subtle" /> : <ChevronRight className="size-4 shrink-0 text-fg-subtle" />}
                  <span className="w-40 shrink-0 truncate text-[13px] font-medium text-fg">{tac.name}</span>
                  <span className="h-2 flex-1 overflow-hidden rounded-full bg-surface-3">
                    <span className={cn('block h-full rounded-full', pct === 100 ? 'bg-success' : 'bg-teal')} style={{ width: `${pct}%` }} />
                  </span>
                  <span className={cn('w-10 shrink-0 text-right text-[13px] font-semibold tabular-nums', tac.coveredCount ? 'text-teal-text' : 'text-fg-subtle')}>
                    {tac.coveredCount}/{tac.techs.length}
                  </span>
                </div>
                <div className="mt-2 flex flex-wrap gap-1.5 pl-7">
                  {tac.techs.map((t) =>
                    covered.has(t.id) ? (
                      <span key={t.id} className="inline-flex items-center gap-1 rounded bg-success-soft px-1.5 py-0.5 text-xs font-medium text-success-text">
                        <Check className="size-3" strokeWidth={3} />
                        {t.name}
                      </span>
                    ) : (
                      <span key={t.id} className="inline-flex items-center rounded border border-dashed border-border-strong px-1.5 py-0.5 text-xs text-fg-muted">
                        {t.name}
                      </span>
                    ),
                  )}
                </div>
              </button>

              {isOpen && (
                <div className="space-y-3 bg-canvas/40 px-5 pt-1 pb-5">
                  {gaps.length === 0 ? (
                    <p className="pl-7 text-[13px] text-success-text">Every catalog technique in {tac.name} has been hunted.</p>
                  ) : (
                    gaps.map((t) => <HuntGuide key={t.id} technique={t} onStartHunt={onStartHunt} />)
                  )}
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </Card>
  );
};

const HuntGuide: React.FC<{ technique: MitreTechnique; onStartHunt: (d: ReportDraft) => void }> = ({ technique: t, onStartHunt }) => {
  const guide = TECHNIQUE_GUIDE[t.id];
  const query = guide?.query ?? (t.sampleQuery ? { language: t.sampleQuery.language, code: t.sampleQuery.query } : undefined);
  const [showQuery, setShowQuery] = useState(false);

  return (
    <div className="rounded-lg border border-border bg-surface p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <span className="font-mono text-xs text-accent-text">{t.id}</span>
          <h4 className="text-sm font-semibold text-fg">{t.name}</h4>
          <p className="mt-0.5 text-[13px] text-fg-muted">{t.description}</p>
        </div>
        <a href={techniqueUrl(t.id)} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-fg-muted hover:text-accent-text">
          MITRE <ExternalLink className="size-3" />
        </a>
      </div>

      {guide && (
        <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
          <div>
            <SectionLabel>
              <span className="inline-flex items-center gap-1.5">
                <Users className="size-3.5" /> Seen in the wild
              </span>
            </SectionLabel>
            <ul className="space-y-2">
              {guide.actors.map((a) => (
                <li key={a.groupId} className="text-[13px] leading-relaxed text-fg-muted">
                  <a href={groupUrl(a.groupId)} target="_blank" rel="noopener noreferrer" className="font-medium text-violet-text hover:underline">
                    {a.name}
                  </a>{' '}
                  — {a.procedure}
                </li>
              ))}
            </ul>
          </div>
          <div className="space-y-3">
            <div>
              <SectionLabel>How to hunt it</SectionLabel>
              <p className="text-[13px] leading-relaxed text-fg-muted">{guide.howToHunt}</p>
            </div>
            <div>
              <SectionLabel>Example of a hit</SectionLabel>
              <p className="rounded-md bg-canvas px-2.5 py-2 font-mono text-[12px] leading-relaxed break-words text-warning-text">{guide.lookFor}</p>
            </div>
          </div>
        </div>
      )}

      {showQuery && query && <CodeBlock className="mt-4" code={query.code} label={`Example query · ${query.language}`} />}

      <div className="mt-4 flex flex-wrap items-center gap-2">
        {query && (
          <Button size="sm" variant="ghost" onClick={() => setShowQuery((v) => !v)}>
            {showQuery ? 'Hide query' : 'Show example query'}
          </Button>
        )}
        <Button
          size="sm"
          variant="primary"
          iconRight={ArrowRight}
          className="ml-auto"
          onClick={() =>
            onStartHunt({
              hypothesisTitle: `Hunt for ${t.name} (${t.id})`,
              hypothesisDescription: guide?.howToHunt ?? t.description,
              techniqueIds: [t.id],
              dataSources: t.dataSources,
              queryLanguage: query?.language,
              queryText: query?.code,
              notes: guide ? `What a hit looks like: ${guide.lookFor}` : undefined,
            })
          }
        >
          Start this hunt
        </Button>
      </div>
    </div>
  );
};
