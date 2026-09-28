import { createContext, useContext } from 'react';
import type { MitreTechnique, ReportDraft, RuleDraft } from '../types';
import type { RouteId } from './routes';
import type { Workspace } from './useWorkspace';

export interface AppActions {
  navigate: (id: RouteId, params?: Record<string, string>) => void;
  /** Open the hunt report form, optionally prefilled. */
  startReport: (draft?: ReportDraft) => void;
  /** Read the pending report draft without consuming it (safe in render/initialisers). */
  peekReportDraft: () => ReportDraft | null;
  /** Discard the pending report draft once the Reports page has picked it up. */
  clearReportDraft: () => void;
  openThr: () => void;
  openMatrix: (technique?: MitreTechnique) => void;
  /** Add a rule to Detection rules (Testing / Staging) and go there. */
  sendToDetections: (draft: RuleDraft) => void;
}

export type AppContextValue = Workspace & AppActions;

export const AppContext = createContext<AppContextValue | null>(null);

export function useApp(): AppContextValue {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp must be used inside <AppContext.Provider>');
  return ctx;
}
