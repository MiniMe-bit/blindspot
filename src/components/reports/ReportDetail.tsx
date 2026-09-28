import React from 'react';
import { Download, Gauge, Printer, ShieldCheck } from 'lucide-react';
import type { ClientOrg, DetectionPlatform, HuntReport, ThreatHuntReportDocument } from '../../types';
import { useApp } from '../../app/AppContext';
import { downloadThreatHuntDoc, printThreatHuntPdf } from '../../utils/thrExporter';
import { formatDate } from '../../lib/coverage';
import { HUNTS_PER_PHASE, phaseCounts, phaseOptions } from '../../lib/phases';
import { Badge, Button, Card, CodeBlock, SectionLabel, outcomeTone, severityTone } from '../ui';

const RULE_PLATFORM: Record<HuntReport['queryLanguage'], DetectionPlatform> = {
  KQL: 'Microsoft Sentinel (KQL)',
  SPL: 'Splunk Enterprise (SPL)',
  Sigma: 'Sigma (Generic)',
  EQL: 'Elasticsearch (EQL)',
};

/** Build an exportable THR document from a plain hunt report, using only what the report contains. */
function thrDocFor(report: HuntReport, client: ClientOrg): ThreatHuntReportDocument {
  if (report.thrDocument) return report.thrDocument;
  const techs = report.techniqueIds.join(', ');
  return {
    hypothesisName: report.hypothesisTitle,
    reportDate: report.reportDate || report.createdAt.split('T')[0],
    executiveSummary: report.hypothesisDescription,
    purpose: `Hunt for ${techs} activity in ${client.name}'s environment.`,
    mitreInformation: `Techniques: ${techs}.`,
    huntMethodology: `Data sources: ${report.dataSources.join(', ') || 'not recorded'}.`,
    potentialDetectionIdeas: '',
    huntQueries: [{ id: 'q-1', platform: report.queryLanguage, title: 'Hunt query', code: report.queryText }],
    huntResults: report.notes || '',
    analysis: `Outcome: ${report.outcome}.`,
    risk: '',
    impact: '',
    recommendation: '',
    references: report.techniqueIds.map((t) => `https://attack.mitre.org/techniques/${t.replace('.', '/')}`),
  };
}

const THR_SECTIONS: Array<[keyof ThreatHuntReportDocument, string]> = [
  ['executiveSummary', 'Executive summary'],
  ['purpose', 'Purpose'],
  ['mitreInformation', 'ATT&CK mapping'],
  ['huntMethodology', 'Methodology'],
  ['potentialDetectionIdeas', 'Detection ideas'],
  ['huntResults', 'Results'],
  ['analysis', 'Analysis'],
  ['risk', 'Risk'],
  ['impact', 'Impact'],
  ['recommendation', 'Recommendation'],
];

export const ReportDetail: React.FC<{ report: HuntReport }> = ({ report }) => {
  const { currentClient, clientReports, navigate, sendToDetections, setReportPhase } = useApp();
  const counts = phaseCounts(clientReports);
  const doc = thrDocFor(report, currentClient);
  const s = report.severityScore;

  return (
    <Card>
      <div className="border-b border-border px-5 py-4">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={outcomeTone(report.outcome)}>{report.outcome}</Badge>
          {s && (
            <Badge tone={severityTone(s.severityLevel)}>
              {s.severityLevel} · {s.compositeScore}
            </Badge>
          )}
          {report.thrDocument && <Badge tone="accent">THR</Badge>}
          <label className="ml-auto flex items-center gap-2 text-xs text-fg-subtle">
            Phase
            <select
              value={report.phase ?? ''}
              onChange={(e) => setReportPhase(report.id, e.target.value ? Number(e.target.value) : undefined)}
              className="h-7 rounded-md border border-border bg-canvas px-2 text-xs font-medium text-fg focus:border-accent focus:outline-none"
              aria-label="Phase"
            >
              <option value="">No phase</option>
              {phaseOptions(clientReports).map((p) => (
                <option key={p} value={p}>
                  Phase {p} ({counts.get(p) ?? 0}/{HUNTS_PER_PHASE})
                </option>
              ))}
            </select>
          </label>
        </div>
        <h2 className="mt-2 text-base font-semibold leading-snug text-fg">{report.hypothesisTitle}</h2>
        <p className="mt-1 text-[13px] text-fg-muted">
          {report.analystName} · {report.weekRange} · Logged {formatDate(report.createdAt)}
        </p>
        <div className="mt-4 flex flex-wrap gap-2">
          <Button size="sm" icon={Gauge} onClick={() => navigate('severity', { report: report.id })}>
            {s ? 'Re-score severity' : 'Score severity'}
          </Button>
          <Button
            size="sm"
            icon={ShieldCheck}
            onClick={() =>
              sendToDetections({
                ruleName: report.hypothesisTitle.slice(0, 80),
                queryLogic: report.queryText,
                techniqueIds: report.techniqueIds,
                tactics: [],
                description: report.hypothesisTitle,
                platform: RULE_PLATFORM[report.queryLanguage],
                huntReportId: report.id,
              })
            }
          >
            Create detection rule
          </Button>
          <div className="ml-auto flex gap-2">
            <Button size="sm" variant="ghost" icon={Download} onClick={() => downloadThreatHuntDoc(doc, currentClient.name, report.analystName, report.outcome)}>
              .doc
            </Button>
            <Button size="sm" variant="ghost" icon={Printer} onClick={() => printThreatHuntPdf(doc, currentClient.name, report.analystName, report.outcome)}>
              PDF
            </Button>
          </div>
        </div>
      </div>

      <div className="space-y-6 px-5 py-5">
        <section>
          <SectionLabel>Hypothesis</SectionLabel>
          <p className="whitespace-pre-wrap text-sm leading-relaxed text-fg-muted">{report.hypothesisDescription}</p>
        </section>

        <section className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <SectionLabel>Techniques</SectionLabel>
            <div className="flex flex-wrap gap-1.5">
              {report.techniqueIds.map((t) => (
                <Badge key={t} mono>
                  {t}
                </Badge>
              ))}
            </div>
          </div>
          <div>
            <SectionLabel>Data sources</SectionLabel>
            <p className="text-[13px] text-fg-muted">{report.dataSources.join(', ') || '—'}</p>
          </div>
        </section>

        <section>
          <SectionLabel>Query</SectionLabel>
          <CodeBlock code={report.queryText} label={report.queryLanguage} />
        </section>

        <section>
          <SectionLabel>Notes</SectionLabel>
          <p className="whitespace-pre-wrap text-sm leading-relaxed text-fg-muted">{report.notes || 'No notes recorded.'}</p>
        </section>

        {report.iocs.length > 0 && (
          <section>
            <SectionLabel>Indicators ({report.iocs.length})</SectionLabel>
            <div className="overflow-x-auto rounded-md border border-border">
              <table className="w-full text-left text-[13px]">
                <thead className="bg-surface-2 text-xs text-fg-subtle">
                  <tr>
                    <th className="px-3 py-2 font-medium">Type</th>
                    <th className="px-3 py-2 font-medium">Value</th>
                    <th className="px-3 py-2 font-medium">Context</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {report.iocs.map((i) => (
                    <tr key={i.id}>
                      <td className="px-3 py-2 text-fg-muted">{i.type}</td>
                      <td className="select-all break-all px-3 py-2 font-mono text-fg">{i.value}</td>
                      <td className="px-3 py-2 text-fg-muted">{i.notes || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {s && (
          <section>
            <SectionLabel>Severity assessment</SectionLabel>
            <dl className="grid grid-cols-2 gap-3 text-[13px] sm:grid-cols-4">
              {(
                [
                  ['Business impact', s.factors.businessImpact, s.factorBreakdown.businessImpactPoints],
                  ['Threat stage', s.factors.threatStage, s.factorBreakdown.threatStagePoints],
                  ['Confidence', s.factors.detectionConfidence, s.factorBreakdown.detectionConfidencePoints],
                  ['Exploitability', s.factors.exploitability, s.factorBreakdown.exploitabilityPoints],
                ] as const
              ).map(([label, value, pts]) => (
                <div key={label} className="rounded-md border border-border px-3 py-2">
                  <dt className="text-xs text-fg-subtle">{label}</dt>
                  <dd className="mt-0.5 text-fg">{value}</dd>
                  <dd className="text-xs text-fg-subtle">{pts} pts</dd>
                </div>
              ))}
            </dl>
            {s.rationale && <p className="mt-3 text-[13px] leading-relaxed text-fg-muted">{s.rationale}</p>}
          </section>
        )}

        {report.thrDocument && (
          <section className="space-y-4 border-t border-border pt-5">
            <h3 className="text-sm font-semibold text-fg">Threat hunt report</h3>
            {THR_SECTIONS.map(([key, label]) => {
              const value = report.thrDocument![key];
              if (typeof value !== 'string' || !value.trim()) return null;
              return (
                <div key={key}>
                  <SectionLabel>{label}</SectionLabel>
                  <p className="whitespace-pre-wrap text-[13px] leading-relaxed text-fg-muted">{value}</p>
                </div>
              );
            })}
            {report.thrDocument.references?.length > 0 && (
              <div>
                <SectionLabel>References</SectionLabel>
                <ul className="list-disc space-y-0.5 pl-5 text-[13px] text-fg-muted">
                  {report.thrDocument.references.map((r, idx) => (
                    <li key={idx} className="break-words">
                      {r}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </section>
        )}
      </div>
    </Card>
  );
};
