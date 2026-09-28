import { useCallback, useEffect, useState } from 'react';
import { DEFAULT_ROUTE, ROUTES, type RouteId } from '../app/routes';

/** Query params from the hash, e.g. `#/reports?id=abc` -> { id: 'abc' }. */
export const hashParams = () => new URLSearchParams(window.location.hash.split('?')[1] ?? '');

const parse = (hash: string): RouteId => {
  const path = hash.replace(/^#/, '').split('?')[0] || '/';
  const match = (Object.values(ROUTES) as Array<(typeof ROUTES)[RouteId]>).find((r) => r.path === path);
  return match ? match.id : DEFAULT_ROUTE;
};

/** Minimal hash router: `#/reports` <-> 'reports'. Keeps back/forward and deep links working. */
export function useHashRoute(): [RouteId, (id: RouteId, params?: Record<string, string>) => void] {
  const [route, setRoute] = useState<RouteId>(() => parse(window.location.hash));

  useEffect(() => {
    const onChange = () => {
      setRoute(parse(window.location.hash));
      window.scrollTo(0, 0);
    };
    window.addEventListener('hashchange', onChange);
    if (!window.location.hash) window.history.replaceState(null, '', `#${ROUTES[DEFAULT_ROUTE].path}`);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);

  const navigate = useCallback((id: RouteId, params?: Record<string, string>) => {
    const query = params ? `?${new URLSearchParams(params).toString()}` : '';
    window.location.hash = `${ROUTES[id].path}${query}`;
  }, []);

  return [route, navigate];
}
