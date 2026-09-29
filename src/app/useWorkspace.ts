import { useCallback, useMemo, useState } from 'react';
import type {
  ClientOrg,
  DetectionRule,
  HuntReport,
  RuleDraft,
  SeverityScoreRecord,
  HuntReference,
  IocHunt,
  TodayHunt,
  User,
} from '../types';
import {
  INITIAL_CLIENTS,
  INITIAL_DETECTION_RULES,
  INITIAL_HUNT_REPORTS,
  INITIAL_TODAYS_HUNTS,
  INITIAL_USERS,
} from '../data/mockData';
import { EXTRA_TODAYS_HUNTS, enrichHunt } from '../data/huntLibrary';
import { LEGACY_SOURCE } from '../lib/huntCatalog';
import { demoIocHunts } from '../data/iocDemo';
import { iocKey } from '../lib/iocHunts';
import { clearPersistedState, usePersistentState } from '../lib/usePersistentState';

const SEED_HUNTS: TodayHunt[] = [...INITIAL_TODAYS_HUNTS, ...EXTRA_TODAYS_HUNTS];

/** Backfill platform queries, references and new seed hunts into hunts saved by an older version. */
function migrateHunts(saved: TodayHunt[]): TodayHunt[] {
  const known = new Set(saved.map((h) => h.id));
  return [...saved, ...SEED_HUNTS.filter((h) => !known.has(h.id))].map((h) => enrichHunt(h, LEGACY_SOURCE));
}

/** Seed clients were renamed; carry the new name, description and logo onto saved clients (telemetry edits are kept). */
function migrateClients(saved: ClientOrg[]): ClientOrg[] {
  return saved.map((c) => {
    const seed = INITIAL_CLIENTS.find((s) => s.id === c.id);
    return seed ? { ...c, name: seed.name, description: seed.description, logoSlug: seed.logoSlug } : c;
  });
}

const SELECTED_CLIENT_KEY = 'blindspot.session.clientId';

/** The client picked in this browser session. Cleared on sign-in and sign-out so every session starts at the client list. */
export function clearClientSelection() {
  try {
    sessionStorage.removeItem(SELECTED_CLIENT_KEY);
  } catch {
    // ignore
  }
}

export interface IocImportResult {
  added: number;
  duplicates: number;
}

/** The signed-in hunter, as returned by /api/auth/me. */
export interface SessionUser {
  id: string;
  username: string;
  name: string;
  email: string;
  role: User['role'];
  /** Signed in with an admin-issued temporary password: must set a new one first. */
  mustChangePassword?: boolean;
}

/**
 * Single source of truth for workspace data.
 * Today this is localStorage-backed demo data; it is the seam where a real API client plugs in.
 */
export function useWorkspace(sessionUser: SessionUser) {
  const [clients, setClients] = usePersistentState<ClientOrg[]>('clients', INITIAL_CLIENTS, migrateClients);
  const [reports, setReports] = usePersistentState<HuntReport[]>('reports', INITIAL_HUNT_REPORTS);
  const [todaysHunts, setTodaysHunts] = usePersistentState<TodayHunt[]>(
    'todaysHunts',
    () => SEED_HUNTS.map((h) => enrichHunt(h, LEGACY_SOURCE)),
    migrateHunts,
  );
  const [rules, setRules] = usePersistentState<DetectionRule[]>('detectionRules', INITIAL_DETECTION_RULES);
  const [iocHunts, setIocHunts] = usePersistentState<IocHunt[]>('iocHunts', () => INITIAL_CLIENTS.flatMap((c) => demoIocHunts(c.id)));
  const [selectedClientId, setSelectedClientId] = useState<string | null>(() => {
    try {
      return sessionStorage.getItem(SELECTED_CLIENT_KEY);
    } catch {
      return null;
    }
  });

  const selectedClient = clients.find((c) => c.id === selectedClientId);
  /** False until the hunter picks a client; client-scoped pages are unavailable until then. */
  const clientSelected = Boolean(selectedClient);
  // Pages only render once a client is selected; the fallback keeps types simple.
  const currentClient = selectedClient ?? clients[0];

  const setCurrentClientId = useCallback((id: string) => {
    setSelectedClientId(id);
    try {
      sessionStorage.setItem(SELECTED_CLIENT_KEY, id);
    } catch {
      // Selection still works for this page load.
    }
  }, []);
  const currentUser: User = useMemo(() => {
    const seed = INITIAL_USERS.find((u) => u.id === sessionUser.id);
    const initials = sessionUser.name.split(' ').map((p) => p[0]).join('').slice(0, 2).toUpperCase();
    return { orgId: 'org-blindspot', huntCount: 0, ...seed, ...sessionUser, avatar: initials };
  }, [sessionUser]);

  // Client-scoped views of the data. Pages should use these, not the unscoped arrays.
  const clientReports = useMemo(() => reports.filter((r) => r.clientId === currentClient.id), [reports, currentClient.id]);
  const clientHunts = useMemo(() => todaysHunts.filter((h) => h.clientId === currentClient.id), [todaysHunts, currentClient.id]);
  const clientRules = useMemo(() => rules.filter((r) => r.clientId === currentClient.id), [rules, currentClient.id]);
  const clientIocHunts = useMemo(() => iocHunts.filter((h) => h.clientId === currentClient.id), [iocHunts, currentClient.id]);

  /** Add uploaded sheet rows for the current client, skipping rows identical (all fields) to ones already stored or earlier in the file. */
  const importIocHunts = useCallback(
    (rows: Array<Omit<IocHunt, 'id' | 'clientId' | 'origin' | 'importedAt'>>): IocImportResult => {
      const seen = new Set(iocHunts.filter((h) => h.clientId === currentClient.id).map(iocKey));
      const now = new Date().toISOString();
      const fresh: IocHunt[] = [];
      rows.forEach((row, i) => {
        const key = iocKey(row);
        if (seen.has(key)) return;
        seen.add(key);
        fresh.push({ ...row, id: `ioc-${Date.now()}-${i}`, clientId: currentClient.id, origin: 'upload', importedAt: now });
      });
      if (fresh.length) setIocHunts((prev) => [...fresh, ...prev]);
      return { added: fresh.length, duplicates: rows.length - fresh.length };
    },
    [iocHunts, currentClient.id, setIocHunts],
  );

  const removeDemoIocHunts = useCallback(
    () => setIocHunts((prev) => prev.filter((h) => !(h.clientId === currentClient.id && h.origin === 'demo'))),
    [currentClient.id, setIocHunts],
  );

  const addReport = useCallback((report: HuntReport) => setReports((prev) => [report, ...prev]), [setReports]);

  const attachSeverity = useCallback(
    (reportId: string, record: SeverityScoreRecord) =>
      setReports((prev) => prev.map((r) => (r.id === reportId ? { ...r, severityScore: record, updatedAt: new Date().toISOString() } : r))),
    [setReports],
  );

  const setReportPhase = useCallback(
    (reportId: string, phase: number | undefined) =>
      setReports((prev) => prev.map((r) => (r.id === reportId ? { ...r, phase, updatedAt: new Date().toISOString() } : r))),
    [setReports],
  );

  const addTodaysHunts = useCallback((hunts: TodayHunt[]) => setTodaysHunts((prev) => [...hunts, ...prev]), [setTodaysHunts]);

  const updateTodaysHunt = useCallback(
    (updated: TodayHunt) => setTodaysHunts((prev) => prev.map((h) => (h.id === updated.id ? updated : h))),
    [setTodaysHunts],
  );

  const addHuntReference = useCallback(
    (huntId: string, ref: HuntReference) =>
      setTodaysHunts((prev) => prev.map((h) => (h.id === huntId ? { ...h, references: [...(h.references ?? []), ref] } : h))),
    [setTodaysHunts],
  );

  const addRule = useCallback((rule: DetectionRule) => setRules((prev) => [rule, ...prev]), [setRules]);

  const updateRule = useCallback(
    (updated: DetectionRule) => setRules((prev) => prev.map((r) => (r.id === updated.id ? updated : r))),
    [setRules],
  );

  /** Create a rule in "Testing / Staging" from a draft. Nothing is pushed to a real SIEM. */
  const createRuleFromDraft = useCallback(
    (draft: RuleDraft): DetectionRule => {
      const rule: DetectionRule = {
        id: `det-rule-${Date.now()}`,
        clientId: currentClient.id,
        huntReportId: draft.huntReportId,
        huntHypothesisTitle: draft.description,
        ruleName: draft.ruleName,
        description: draft.description,
        platform: draft.platform,
        severity: 'High',
        status: 'Testing / Staging',
        techniqueIds: draft.techniqueIds,
        tactics: draft.tactics.length ? draft.tactics : ['Execution'],
        queryLogic: draft.queryLogic,
        targetDataSources: currentClient.primaryTelemetry.slice(0, 2),
        targetEnvironment: '',
        deployedBy: currentUser.name,
        sentDate: new Date().toISOString(),
        totalAlertsTriggered: 0,
        falsePositiveRatePct: 0,
        clientApprover: '',
      };
      addRule(rule);
      return rule;
    },
    [addRule, currentClient, currentUser.name],
  );

  const updateClient = useCallback(
    (updated: ClientOrg) => setClients((prev) => prev.map((c) => (c.id === updated.id ? updated : c))),
    [setClients],
  );

  const resetDemoData = useCallback(() => {
    clearPersistedState();
    window.location.reload();
  }, []);

  return {
    clients,
    currentClient,
    clientSelected,
    currentUser,
    setCurrentClientId,
    reports,
    todaysHunts,
    rules,
    clientReports,
    clientIocHunts,
    iocHunts,
    importIocHunts,
    removeDemoIocHunts,
    clientHunts,
    clientRules,
    addReport,
    attachSeverity,
    setReportPhase,
    addTodaysHunts,
    updateTodaysHunt,
    addHuntReference,
    addRule,
    updateRule,
    createRuleFromDraft,
    updateClient,
    resetDemoData,
  };
}

export type Workspace = ReturnType<typeof useWorkspace>;
