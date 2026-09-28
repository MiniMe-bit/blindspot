import React, { useState } from 'react';
import { ClientOrg, IndustryVertical } from '../types';
import { ALL_DATA_SOURCES } from '../data/mitreAttck';
import { 
  Building2, 
  X, 
  ShieldCheck, 
  Plus, 
  Check, 
  SlidersHorizontal,
  Server
} from 'lucide-react';

interface ClientManagementModalProps {
  isOpen: boolean;
  onClose: () => void;
  clients: ClientOrg[];
  currentClient: ClientOrg;
  onSelectClient: (client: ClientOrg) => void;
  onUpdateClient: (updated: ClientOrg) => void;
}

export const ClientManagementModal: React.FC<ClientManagementModalProps> = ({
  isOpen,
  onClose,
  clients,
  currentClient,
  onSelectClient,
  onUpdateClient,
}) => {
  const [activeClient, setActiveClient] = useState<ClientOrg>(currentClient);
  const [telemetrySources, setTelemetrySources] = useState<string[]>(
    currentClient.primaryTelemetry
  );
  const [savedSuccess, setSavedSuccess] = useState(false);

  if (!isOpen) return null;

  const handleToggleTelemetry = (source: string) => {
    if (telemetrySources.includes(source)) {
      setTelemetrySources(telemetrySources.filter((s) => s !== source));
    } else {
      setTelemetrySources([...telemetrySources, source]);
    }
  };

  const handleSave = () => {
    const updated: ClientOrg = {
      ...activeClient,
      primaryTelemetry: telemetrySources,
    };
    onUpdateClient(updated);
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-surface border border-border rounded-lg w-full max-w-3xl flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950">
          <div className="flex items-center gap-2">
            <Building2 className="w-5 h-5 text-cyan-400" />
            <div>
              <h2 className="text-base font-bold text-white tracking-tight">Organization & Telemetry Management</h2>
              <p className="text-[11px] text-slate-400">Configure client threat profiles, data source onboarding, and risk tolerances.</p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-5 text-xs">
          {/* Client Selector List */}
          <div>
            <label className="block text-slate-400 font-semibold uppercase tracking-wider text-[11px] mb-2">
              Select Client Organization
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              {clients.map((c) => {
                const isSelected = activeClient.id === c.id;
                return (
                  <button
                    key={c.id}
                    onClick={() => {
                      setActiveClient(c);
                      setTelemetrySources(c.primaryTelemetry);
                    }}
                    className={`p-3 rounded-lg border text-left transition-colors cursor-pointer ${
                      isSelected
                        ? 'bg-slate-800 border-cyan-500 ring-1 ring-cyan-500/40'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <div className="font-bold text-white text-xs">{c.name}</div>
                    <div className="text-[10px] text-cyan-400 uppercase font-mono mt-0.5">{c.industry}</div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Client Details Preview */}
          <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-3">
            <div className="flex justify-between items-start">
              <div>
                <h3 className="text-sm font-bold text-white">{activeClient.name}</h3>
                <p className="text-slate-300 text-[11px] mt-0.5">{activeClient.description}</p>
              </div>
              <button
                onClick={() => {
                  onSelectClient(activeClient);
                  onClose();
                }}
                className="px-2.5 py-1 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold rounded text-[11px] shrink-0 cursor-pointer"
              >
                Set as Active
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 pt-2 border-t border-slate-800/80 text-[11px] font-mono">
              <div>
                <span className="text-slate-500 block">Risk Profile:</span>
                <span className="text-slate-200 font-bold">{activeClient.threatProfile.riskTolerance}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Adversary Focus:</span>
                <span className="text-amber-300 truncate block">
                  {activeClient.threatProfile.primaryAdversaries.slice(0, 2).join(', ')}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">Compliance:</span>
                <span className="text-cyan-300 truncate block">
                  {activeClient.threatProfile.complianceFrameworks.join(', ')}
                </span>
              </div>
            </div>
          </div>

          {/* Telemetry Onboarding Checkbox Matrix */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-slate-300 font-semibold uppercase tracking-wider text-[11px]">
                Onboarded Telemetry Feeds ({telemetrySources.length} active)
              </label>
              <span className="text-[11px] text-slate-500">Used to flag telemetry gaps on hunts and intel</span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 bg-slate-950 p-3 rounded-lg border border-slate-800 max-h-48 overflow-y-auto scrollbar-thin">
              {ALL_DATA_SOURCES.map((src) => {
                const active = telemetrySources.includes(src);
                return (
                  <label
                    key={src}
                    className="flex items-center gap-2 cursor-pointer p-1.5 rounded hover:bg-slate-900 transition-colors"
                  >
                    <input
                      type="checkbox"
                      checked={active}
                      onChange={() => handleToggleTelemetry(src)}
                      className="rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0"
                    />
                    <span className={`text-[11px] truncate ${active ? 'text-slate-200 font-medium' : 'text-slate-500'}`}>
                      {src}
                    </span>
                  </label>
                );
              })}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950 flex items-center justify-between">
          <span className="text-[11px] text-slate-500">Changes are saved in this browser.</span>
          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-white"
            >
              Cancel
            </button>
            <button
              onClick={handleSave}
              className="flex items-center gap-1.5 px-4 py-1.5 text-xs font-semibold rounded bg-cyan-600 hover:bg-cyan-500 text-white cursor-pointer transition-colors shadow-sm"
            >
              {savedSuccess ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-300" />
                  <span>Telemetry Saved!</span>
                </>
              ) : (
                <span>Save Telemetry Profile</span>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
