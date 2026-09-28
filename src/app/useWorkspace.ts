import { useCallback, useMemo } from 'react';
import type {
  ClientOrg,
  DetectionRule,
  HuntReport,
  RuleDraft,
  SeverityScoreRecord,
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
import { clearPersistedState, usePersistentState } from '../lib/usePersistentState';

/**
 * Single source of truth for workspace data.
 * Today this is localStorage-backed demo data; it is the seam where a real API client plugs in.
 */
export function useWorkspace() {
  const [clients, setClients] = usePersistentState<ClientOrg[]>('clients', INITIAL_CLIENTS);
  const [reports, setReports] = usePersistentState<HuntReport[]>('reports', INITIAL_HUNT_REPORTS);
  const [todaysHunts, setTodaysHunts] = usePersistentState<TodayHunt[]>('todaysHunts', INITIAL_TODAYS_HUNTS);
  const [rules, setRules] = usePersistentState<DetectionRule[]>('detectionRules', INITIAL_DETECTION_RULES);
  const [currentClientId, setCurrentClientId] = usePersistentState<string>('currentClientId', INITIAL_CLIENTS[0].id);
  const [currentUserId, setCurrentUserId] = usePersistentState<string>('currentUserId', INITIAL_USERS[0].id);

  const users: User[] = INITIAL_USERS;
  const currentClient = clients.find((c) => c.id === currentClientId) ?? clients[0];
  const currentUser = users.find((u) => u.id === currentUserId) ?? users[0];

  // Client-scoped views of the data. Pages should use these, not the unscoped arrays.
  const clientReports = useMemo(() => reports.filter((r) => r.clientId === currentClient.id), [reports, currentClient.id]);
  const clientHunts = useMemo(() => todaysHunts.filter((h) => h.clientId === currentClient.id), [todaysHunts, currentClient.id]);
  const clientRules = useMemo(() => rules.filter((r) => r.clientId === currentClient.id), [rules, currentClient.id]);

  const addReport = useCallback((report: HuntReport) => setReports((prev) => [report, ...prev]), [setReports]);

  const attachSeverity = useCallback(
    (reportId: string, record: SeverityScoreRecord) =>
      setReports((prev) => prev.map((r) => (r.id === reportId ? { ...r, severityScore: record, updatedAt: new Date().toISOString() } : r))),
    [setReports],
  );

  const addTodaysHunts = useCallback((hunts: TodayHunt[]) => setTodaysHunts((prev) => [...hunts, ...prev]), [setTodaysHunts]);

  const updateTodaysHunt = useCallback(
    (updated: TodayHunt) => setTodaysHunts((prev) => prev.map((h) => (h.id === updated.id ? updated : h))),
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
    users,
    currentClient,
    currentUser,
    setCurrentClientId,
    setCurrentUserId,
    reports,
    clientReports,
    clientHunts,
    clientRules,
    addReport,
    attachSeverity,
    addTodaysHunts,
    updateTodaysHunt,
    addRule,
    updateRule,
    createRuleFromDraft,
    updateClient,
    resetDemoData,
  };
}

export type Workspace = ReturnType<typeof useWorkspace>;
