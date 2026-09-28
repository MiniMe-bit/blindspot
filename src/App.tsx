/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useMemo, useRef, useState } from 'react';
import type { MitreTechnique, ReportDraft, RuleDraft } from './types';
import { useWorkspace } from './app/useWorkspace';
import { AppContext, type AppContextValue } from './app/AppContext';
import { ROUTES, type RouteId } from './app/routes';
import { useHashRoute } from './lib/useHashRoute';
import { draftFromTechnique } from './lib/drafts';
import { ToastProvider, useToast } from './components/ui';
import { NavRail } from './components/layout/NavRail';
import { TopBar } from './components/layout/TopBar';
import { OverviewView } from './components/OverviewView';
import { TodaysHuntsView } from './components/TodaysHuntsView';
import { ThreatIntelView } from './components/ThreatIntelView';
import { ReportsView } from './components/ReportsView';
import { DetectionsView } from './components/DetectionsView';
import { AttackHeatmapView } from './components/AttackHeatmapView';
import { SeverityScoringView } from './components/SeverityScoringView';
import { DeckGeneratorView } from './components/DeckGeneratorView';
import { MitreMatrixModal } from './components/MitreMatrixModal';
import { ClientManagementModal } from './components/ClientManagementModal';
import { CreateTHRModal } from './components/CreateTHRModal';

const PAGES: Record<RouteId, React.FC> = {
  overview: OverviewView,
  hunts: TodaysHuntsView,
  intel: ThreatIntelView,
  reports: ReportsView,
  detections: DetectionsView,
  coverage: AttackHeatmapView,
  severity: SeverityScoringView,
  decks: DeckGeneratorView,
};

const SIDEBAR_KEY = 'blindspot.ui.sidebarCollapsed';

function Shell() {
  const ws = useWorkspace();
  const toast = useToast();
  const [route, navigate] = useHashRoute();

  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem(SIDEBAR_KEY) === '1';
    } catch {
      return false;
    }
  });
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [clientsOpen, setClientsOpen] = useState(false);
  const [thrOpen, setThrOpen] = useState(false);
  const [matrix, setMatrix] = useState<{ open: boolean; technique: MitreTechnique | null }>({ open: false, technique: null });
  const reportDraft = useRef<ReportDraft | null>(null);

  const toggleCollapsed = () =>
    setCollapsed((v) => {
      try {
        localStorage.setItem(SIDEBAR_KEY, v ? '0' : '1');
      } catch {
        // ignore
      }
      return !v;
    });

  const startReport = useCallback(
    (draft?: ReportDraft) => {
      reportDraft.current = draft ?? { hypothesisTitle: '', techniqueIds: [] };
      if (route === 'reports') {
        // Already on the page: force the page to pick up the new draft.
        window.dispatchEvent(new Event('blindspot:report-draft'));
      } else {
        navigate('reports');
      }
    },
    [navigate, route],
  );

  const peekReportDraft = useCallback(() => reportDraft.current, []);
  const clearReportDraft = useCallback(() => {
    reportDraft.current = null;
  }, []);

  const sendToDetections = useCallback(
    (draft: RuleDraft) => {
      const rule = ws.createRuleFromDraft(draft);
      toast(`"${rule.ruleName}" added to Detection rules as Testing / Staging.`);
      navigate('detections');
    },
    [ws, toast, navigate],
  );

  const ctx: AppContextValue = useMemo(
    () => ({
      ...ws,
      navigate,
      startReport,
      peekReportDraft,
      clearReportDraft,
      openThr: () => setThrOpen(true),
      openMatrix: (technique?: MitreTechnique) => setMatrix({ open: true, technique: technique ?? null }),
      sendToDetections,
    }),
    [ws, navigate, startReport, peekReportDraft, clearReportDraft, sendToDetections],
  );

  const Page = PAGES[route];

  return (
    <AppContext.Provider value={ctx}>
      <div className="flex min-h-screen bg-canvas text-fg">
        <NavRail
          current={route}
          onNavigate={navigate}
          collapsed={collapsed}
          onToggleCollapsed={toggleCollapsed}
          mobileOpen={mobileNavOpen}
          onCloseMobile={() => setMobileNavOpen(false)}
          onOpenClients={() => setClientsOpen(true)}
        />

        <div className="flex min-w-0 flex-1 flex-col">
          <TopBar
            route={route}
            onOpenMobileNav={() => setMobileNavOpen(true)}
            clients={ws.clients}
            currentClient={ws.currentClient}
            onSelectClient={ws.setCurrentClientId}
            onManageClients={() => setClientsOpen(true)}
            users={ws.users}
            currentUser={ws.currentUser}
            onSelectUser={ws.setCurrentUserId}
            onResetDemoData={ws.resetDemoData}
          />

          <main className="flex-1 px-4 py-6 sm:px-6 lg:px-8" aria-label={ROUTES[route].label}>
            <div className="mx-auto w-full max-w-7xl">
              {/* key: remount page state when the client changes */}
              <Page key={`${route}:${ws.currentClient.id}`} />
            </div>
          </main>
        </div>
      </div>

      {thrOpen && (
        <CreateTHRModal
          isOpen
          onClose={() => setThrOpen(false)}
          currentClient={ws.currentClient}
          currentUser={ws.currentUser}
          onSaveReport={(r) => {
            ws.addReport(r);
            toast('Threat hunt report saved to Hunt reports.');
          }}
        />
      )}

      {matrix.open && (
        <MitreMatrixModal
          isOpen
          onClose={() => setMatrix({ open: false, technique: null })}
          selectedInitialTechnique={matrix.technique}
          reports={ws.clientReports}
          onSelectTechniqueForHunt={(techId) => {
            setMatrix({ open: false, technique: null });
            startReport(draftFromTechnique(techId));
          }}
        />
      )}

      {clientsOpen && (
        <ClientManagementModal
          isOpen
          onClose={() => setClientsOpen(false)}
          clients={ws.clients}
          currentClient={ws.currentClient}
          onSelectClient={(c) => ws.setCurrentClientId(c.id)}
          onUpdateClient={(c) => {
            ws.updateClient(c);
            toast(`Telemetry profile for ${c.name} saved.`);
          }}
        />
      )}
    </AppContext.Provider>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <Shell />
    </ToastProvider>
  );
}
