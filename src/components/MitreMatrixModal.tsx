import React, { useState } from 'react';
import { MitreTactic, MitreTechnique, HuntReport } from '../types';
import { MITRE_TACTICS, MITRE_TECHNIQUES } from '../data/mitreAttck';
import { 
  X, 
  Search, 
  Layers, 
  CheckCircle2, 
  AlertCircle, 
  ArrowRight, 
  Terminal, 
  Database,
  ExternalLink,
  Filter
} from 'lucide-react';

interface MitreMatrixModalProps {
  isOpen: boolean;
  onClose: () => void;
  selectedInitialTechnique?: MitreTechnique | null;
  reports: HuntReport[];
  onSelectTechniqueForHunt: (techId: string) => void;
}

export const MitreMatrixModal: React.FC<MitreMatrixModalProps> = ({
  isOpen,
  onClose,
  selectedInitialTechnique,
  reports,
  onSelectTechniqueForHunt,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [coverageFilter, setCoverageFilter] = useState<'all' | 'covered' | 'uncovered'>('all');
  const [selectedTactic, setSelectedTactic] = useState<string>('all');
  const [activeTechnique, setActiveTechnique] = useState<MitreTechnique | null>(
    selectedInitialTechnique || MITRE_TECHNIQUES[0]
  );

  if (!isOpen) return null;

  // Set of covered technique IDs
  const coveredIds = new Set<string>();
  reports.forEach((r) => {
    r.techniqueIds.forEach((t) => {
      coveredIds.add(t);
      coveredIds.add(t.split('.')[0]);
    });
  });

  const filteredTechniques = MITRE_TECHNIQUES.filter((tech) => {
    const isCovered = coveredIds.has(tech.id);
    if (coverageFilter === 'covered' && !isCovered) return false;
    if (coverageFilter === 'uncovered' && isCovered) return false;
    if (selectedTactic !== 'all' && tech.tactic !== selectedTactic) return false;

    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matchId = tech.id.toLowerCase().includes(term);
      const matchName = tech.name.toLowerCase().includes(term);
      const matchDesc = tech.description.toLowerCase().includes(term);
      const matchSub = tech.subTechniques?.some(
        (s) => s.id.toLowerCase().includes(term) || s.name.toLowerCase().includes(term)
      );
      if (!matchId && !matchName && !matchDesc && !matchSub) return false;
    }

    return true;
  });

  const activeTechniqueReports = activeTechnique
    ? reports.filter(
        (r) =>
          r.techniqueIds.includes(activeTechnique.id) ||
          r.techniqueIds.some((t) => t.startsWith(activeTechnique.id))
      )
    : [];

  const isCurrentCovered = activeTechnique ? coveredIds.has(activeTechnique.id) : false;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-6xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-cyan-600/20 border border-cyan-500/40 flex items-center justify-center">
              <Layers className="w-4 h-4 text-cyan-400" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white tracking-tight">MITRE ATT&CK® Enterprise Matrix Explorer</h2>
              <p className="text-[11px] text-slate-400">
                Explore covered vs uncovered adversary techniques and inspect past investigation logs.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Filter Toolbar */}
        <div className="px-6 py-3 border-b border-slate-800 bg-slate-900 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div className="relative flex-1 max-w-sm">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by ID (e.g. T1059), technique name, or sub-technique..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {/* Tactic dropdown */}
            <select
              aria-label="Filter by MITRE Tactic"
              value={selectedTactic}
              onChange={(e) => setSelectedTactic(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-300 text-xs focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All 14 Tactics</option>
              {MITRE_TACTICS.map((t) => (
                <option key={t.id} value={t.name}>
                  {t.name} ({t.shortCode})
                </option>
              ))}
            </select>

            {/* Coverage Segmented buttons */}
            <div className="flex items-center bg-slate-950 border border-slate-800 rounded p-0.5">
              {[
                { id: 'all', label: 'All' },
                { id: 'covered', label: 'Covered' },
                { id: 'uncovered', label: 'Wanna Be Covered (Gaps)' },
              ].map((btn) => (
                <button
                  key={btn.id}
                  onClick={() => setCoverageFilter(btn.id as any)}
                  className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                    coverageFilter === btn.id
                      ? 'bg-slate-800 text-cyan-300 font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {btn.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* MIDDLE SECTION: 14-Tactics Covered & Wanna Be Covered Heatmap Strip */}
        <div className="px-6 py-2.5 bg-slate-950/90 border-b border-slate-800/80 space-y-2">
          <div className="flex items-center justify-between text-[11px]">
            <div className="flex items-center gap-2">
              <span className="font-semibold text-slate-200">Tactics Heatmap:</span>
              <span className="text-slate-400">
                Click any tactic to filter techniques. Green = Covered, Amber/Rose = Wanna Be Covered (Gaps)
              </span>
            </div>
            {selectedTactic !== 'all' && (
              <button
                onClick={() => setSelectedTactic('all')}
                className="text-cyan-400 hover:underline cursor-pointer font-medium"
              >
                Reset to All Tactics
              </button>
            )}
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-1.5 text-xs">
            {/* All Tactics Reset Card */}
            <button
              onClick={() => setSelectedTactic('all')}
              className={`p-1.5 rounded text-left transition-colors border cursor-pointer ${
                selectedTactic === 'all'
                  ? 'bg-slate-800 text-cyan-300 border-cyan-500 font-bold'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200 border-slate-800'
              }`}
            >
              <div className="flex items-center justify-between font-mono text-[9px] text-slate-500">
                <span>ALL</span>
                <span className="text-cyan-400">{coveredIds.size}/{MITRE_TECHNIQUES.length}</span>
              </div>
              <div className="truncate font-semibold text-[10.5px] text-white">All Tactics</div>
            </button>

            {/* 14 Individual Tactics Cards */}
            {MITRE_TACTICS.map((tac) => {
              const tacTechs = MITRE_TECHNIQUES.filter((t) => t.tactic === tac.name);
              const cov = tacTechs.filter((t) => coveredIds.has(t.id)).length;
              const gaps = tacTechs.length - cov;
              const isSelected = selectedTactic === tac.name;
              const pct = tacTechs.length > 0 ? Math.round((cov / tacTechs.length) * 100) : 0;
              const isCovered = cov > 0;

              return (
                <button
                  key={tac.id}
                  onClick={() => setSelectedTactic(isSelected ? 'all' : tac.name)}
                  className={`p-1.5 rounded text-left transition-colors border cursor-pointer relative overflow-hidden ${
                    isSelected
                      ? 'bg-cyan-950 text-cyan-200 border-cyan-400 font-bold shadow-sm'
                      : isCovered
                      ? 'bg-slate-900/90 text-slate-300 hover:border-emerald-600/80 border-slate-800'
                      : 'bg-slate-900/60 text-slate-400 hover:border-amber-600/80 border-slate-800/80'
                  }`}
                  title={`${tac.name}: ${cov} covered, ${gaps} wanna be covered`}
                >
                  <div className="flex items-center justify-between font-mono text-[9px]">
                    <span className="text-slate-500">{tac.shortCode}</span>
                    <span className={cov > 0 ? 'text-emerald-400 font-semibold' : 'text-amber-400 font-semibold'}>
                      {cov > 0 ? `${cov} cov` : `${gaps} gap`}
                    </span>
                  </div>
                  <div className="truncate font-medium text-[10px] text-slate-200">
                    {tac.name.replace('Enterprise', '')}
                  </div>
                  {/* Heatmap status bar */}
                  <div className="w-full bg-slate-800 h-1 rounded-full mt-1 overflow-hidden">
                    <div
                      style={{ width: `${pct}%` }}
                      className={`h-full ${cov > 0 ? 'bg-emerald-400' : 'bg-transparent'}`}
                    />
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Modal Main Split: Technique List (Left 5 Cols) + Deep Dive (Right 7 Cols) */}
        <div className="grid grid-cols-1 md:grid-cols-12 flex-1 overflow-hidden">
          {/* Technique Catalog List (Left) */}
          <div className="md:col-span-5 border-r border-slate-800 overflow-y-auto p-4 space-y-2 max-h-[600px] scrollbar-thin">
            <div className="text-[11px] text-slate-500 font-mono pb-1 flex justify-between">
              <span>Showing {filteredTechniques.length} techniques</span>
              <span>{coveredIds.size} Covered in Org</span>
            </div>

            {filteredTechniques.map((tech) => {
              const isCovered = coveredIds.has(tech.id);
              const isSelected = activeTechnique?.id === tech.id;
              const huntsCount = reports.filter((r) =>
                r.techniqueIds.includes(tech.id) || r.techniqueIds.some((t) => t.startsWith(tech.id))
              ).length;

              return (
                <div
                  key={tech.id}
                  onClick={() => setActiveTechnique(tech)}
                  className={`p-3 rounded-lg border text-left cursor-pointer transition-colors space-y-1 ${
                    isSelected
                      ? 'bg-slate-800/90 border-cyan-500 shadow-sm'
                      : 'bg-slate-950/70 border-slate-800/80 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between text-[11px] font-mono">
                    <span className="font-bold text-cyan-400">{tech.id}</span>
                    <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                      isCovered
                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        : 'bg-slate-900 text-rose-400 border border-slate-800'
                    }`}>
                      {isCovered ? `Covered (${huntsCount})` : 'Uncovered'}
                    </span>
                  </div>
                  <div className="text-xs font-semibold text-white leading-snug">{tech.name}</div>
                  <div className="text-[11px] text-slate-400 font-mono truncate">{tech.tactic}</div>
                </div>
              );
            })}

            {filteredTechniques.length === 0 && (
              <div className="py-12 text-center text-xs text-slate-500">
                No techniques matched your search filters.
              </div>
            )}
          </div>

          {/* Deep-Dive Technique Detail (Right) */}
          <div className="md:col-span-7 overflow-y-auto p-6 space-y-5 max-h-[600px] scrollbar-thin bg-slate-900/60">
            {activeTechnique ? (
              <>
                {/* Header */}
                <div className="flex items-start justify-between border-b border-slate-800 pb-3">
                  <div>
                    <div className="flex items-center gap-2 font-mono text-xs">
                      <span className="text-cyan-400 font-bold">{activeTechnique.id}</span>
                      <span className="text-slate-600">/</span>
                      <span className="text-slate-300 font-semibold">{activeTechnique.tactic} ({activeTechnique.tacticId})</span>
                    </div>
                    <h3 className="text-lg font-bold text-white tracking-tight mt-1">{activeTechnique.name}</h3>
                  </div>

                  <button
                    onClick={() => {
                      onSelectTechniqueForHunt(activeTechnique.id);
                      onClose();
                    }}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white cursor-pointer shadow-sm transition-colors shrink-0"
                  >
                    <span>Hunt This Technique</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>

                {/* Description */}
                <div>
                  <h4 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">
                    Technique Overview
                  </h4>
                  <p className="text-xs text-slate-200 leading-relaxed bg-slate-950 p-3.5 rounded border border-slate-800">
                    {activeTechnique.description}
                  </p>
                </div>

                {/* Sub-Techniques */}
                {activeTechnique.subTechniques && activeTechnique.subTechniques.length > 0 && (
                  <div>
                    <h4 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                      Sub-Techniques ({activeTechnique.subTechniques.length})
                    </h4>
                    <div className="space-y-1.5">
                      {activeTechnique.subTechniques.map((sub) => {
                        const isSubCovered = coveredIds.has(sub.id);
                        return (
                          <div
                            key={sub.id}
                            className="bg-slate-950 p-2.5 rounded border border-slate-800 flex items-start justify-between gap-3 text-xs"
                          >
                            <div>
                              <div className="font-mono text-[11px] font-semibold text-cyan-300">
                                {sub.id} · {sub.name}
                              </div>
                              <p className="text-[11px] text-slate-400 mt-0.5">{sub.description}</p>
                            </div>
                            <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-bold shrink-0 ${
                              isSubCovered
                                ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                                : 'bg-slate-900 text-slate-500 border border-slate-800'
                            }`}>
                              {isSubCovered ? 'Covered' : 'Uncovered'}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Telemetry & Sample Query */}
                <div className="space-y-3">
                  <div>
                    <h4 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">
                      Required Data Sources
                    </h4>
                    <div className="flex flex-wrap gap-1.5">
                      {activeTechnique.dataSources.map((ds) => (
                        <span
                          key={ds}
                          className="px-2 py-0.5 text-[11px] font-mono bg-slate-950 text-slate-300 rounded border border-slate-800"
                        >
                          {ds}
                        </span>
                      ))}
                    </div>
                  </div>

                  {activeTechnique.sampleQuery && (
                    <div>
                      <h4 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1 font-mono">
                        Starter Detection Query ({activeTechnique.sampleQuery.language})
                      </h4>
                      <pre className="bg-slate-950 p-3 rounded text-[11px] font-mono text-cyan-200 overflow-x-auto border border-slate-800 leading-relaxed scrollbar-thin">
                        {activeTechnique.sampleQuery.query}
                      </pre>
                    </div>
                  )}
                </div>

                {/* Past Hunts on this Technique */}
                <div>
                  <h4 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                    Past Organization Investigations ({activeTechniqueReports.length})
                  </h4>
                  {activeTechniqueReports.length > 0 ? (
                    <div className="space-y-1.5">
                      {activeTechniqueReports.map((r) => (
                        <div key={r.id} className="bg-slate-950 p-2.5 rounded border border-slate-800 flex items-center justify-between text-xs">
                          <div>
                            <div className="font-semibold text-white">{r.hypothesisTitle}</div>
                            <div className="text-[10px] text-slate-400 font-mono">
                              {r.weekRange} · Hunter: {r.analystName}
                            </div>
                          </div>
                          <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                            r.outcome === 'True Positive'
                              ? 'text-emerald-400 bg-emerald-950'
                              : 'text-slate-400 bg-slate-900'
                          }`}>
                            {r.outcome}
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-3 bg-slate-950 rounded border border-slate-800 text-xs text-slate-500">
                      This technique has no recorded hunts for this client yet. Click "Hunt This Technique" to establish coverage.
                    </div>
                  )}
                </div>
              </>
            ) : (
              <div className="p-12 text-center text-xs text-slate-500">
                Select a technique from the catalog on the left to view details.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
