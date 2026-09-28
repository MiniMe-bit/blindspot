# Blindspot

Threat hunting workspace for managed hunting teams: log hunt reports, track ATT&CK coverage per client,
promote hunts to detection rules, score findings, and produce executive briefings.

> **Status:** MVP in progress. All data is demo data stored in the browser (`localStorage`).
> Use **Account menu → Reset demo data** to start over.

## Run locally

Prerequisites: Node.js 20+

```bash
npm install
npm run dev        # http://localhost:3000
npm run lint       # type-check
```

Optional AI features need a Gemini key in `.env.local`:

```
GEMINI_API_KEY=...
GEMINI_MODEL=gemini-3.8-flash   # optional override
```

Without a key the app still works. AI-backed actions tell the user when they fall back to curated or
template content, and document import is disabled rather than guessed.

## Structure

```
src/
  App.tsx                 App shell composition, modals, cross-page actions
  app/
    routes.ts             Route + nav-rail definitions (single source of truth)
    useWorkspace.ts       Workspace data + mutations (swap for an API client later)
    AppContext.tsx        useApp(): workspace data + navigate/startReport/sendToDetections
  components/
    layout/               NavRail, TopBar
    ui/                   Design-system primitives (Button, Card, Badge, Field, Modal, ...)
    reports/              Hunt report form, detail, suggestions
    *View.tsx             One file per routed page
  lib/                    Pure helpers (coverage math, hash router, persistence, drafts)
  data/                   Demo seed data and the ATT&CK catalog subset
server.ts                 Express + Vite dev server and /api/ai/* endpoints
```

## UI conventions

- Every page starts with `<PageHeader>`; pages never render their own brand or nav.
- Use semantic color tokens (`bg-surface`, `text-fg-muted`, `border-border`, `bg-accent`, `text-danger-text`)
  defined in `src/index.css`. Don't introduce raw palette colors, glows or gradients.
- Status colors carry meaning only: danger = critical/true positive, warning = high/gap, success = covered/live.
- Every number shown must be computed from real data. No placeholder metrics or simulated results.
- Features that call AI must surface `fallback` responses to the user.

## Revamp status

| Page | State |
| --- | --- |
| Shell (nav rail, top bar, routing) | Rebuilt |
| Overview, Today's hunts, Threat intel, Hunt reports, Detection rules, Severity scoring, ATT&CK coverage | Rebuilt on the design system |
| Executive decks | Honest data, new header; slide styling still legacy |
| Create THR modal, Matrix explorer, Clients modal | Legacy styling (toned down via transitional palette remap in `index.css`) |

`legacy/` holds the pre-revamp components for reference; they are not compiled.
