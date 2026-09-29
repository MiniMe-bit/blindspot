# Blindspot

Threat hunting workspace for managed hunting teams. Hunters sign in, pick a client, and work that
client's hunts: hypothesis records, daily IOC hunting, threat intel, ATT&CK coverage, detection rules,
severity scoring and executive PowerPoint briefings.

> **Status:** MVP in progress. Workspace data (clients, records, IOC hunts, rules) is demo data stored in
> the browser (`localStorage`). Hunter accounts are stored on the server. Reset the browser data from
> **Account menu → Reset demo data**.

## Contents

- [Features](#features)
- [Getting started](#getting-started)
- [Configuration](#configuration)
- [Hunter accounts](#hunter-accounts)
- [Daily IOC Hunting sheet format](#daily-ioc-hunting-sheet-format)
- [Scripts](#scripts)
- [Project structure](#project-structure)
- [UI conventions](#ui-conventions)
- [Revamp status](#revamp-status)

## Features

| Area | What it does |
| --- | --- |
| **Sign-in** | Username/password per hunter, change password from the account menu, 12-hour sessions. |
| **All clients** | Landing page after sign-in. Client pages stay locked until a client is picked. |
| **Client overview** | Client profile, KPI tiles, findings, ATT&CK coverage by tactic with hunt guides, Threat Intelligence [TTP Hunts] for the client's sector. |
| **Hypothesis Record** | Searchable hunt records, grouped into phases of 10 hunts. New records via form or document/THR upload. |
| **Daily IOC Hunting** | Upload the daily threat-intel IOC / CVE-check sheet; totals, category weightage, escalations, de-duplicated log. |
| **Threat intel** | Sector advisories with ready-made hunt packages. |
| **What's New** | Prioritised hunt ideas with queries for CrowdStrike (FQL), Microsoft Defender (KQL), Trend Micro Vision One, Elastic, Sigma and Splunk, plus reference reading. |
| **Detection** | Detection rules promoted from hunts, and the ATT&CK coverage matrix. |
| **Reporting** | Severity scoring and executive decks exported as PowerPoint (`.pptx`), including a Daily IOC Hunting slide. |

## Getting started

**Prerequisites:** Node.js 20 or later.

```bash
npm install
npm run dev
```

Open http://localhost:3000 and sign in with an account from `data/initial-credentials.txt`
(created on first start; see [Hunter accounts](#hunter-accounts)).

**Production build:**

```bash
npm run build
NODE_ENV=production npm start
```

## Configuration

Create a `.env` file in the project root (see `.env.example`). The server reads `.env` only.

| Variable | Required | Purpose |
| --- | --- | --- |
| `SESSION_SECRET` | Yes, in production | Signs login sessions. Without it a random secret is used and everyone is signed out on every restart. |
| `GEMINI_API_KEY` | No | Enables AI features (hunt ideas, narratives, document import). Without it, AI actions say they fell back to curated content. |
| `GEMINI_MODEL` | No | Overrides the Gemini model (default `gemini-3.8-flash`). |
| `PORT` | No | Server port (default `3000`). |
| `NODE_ENV` | No | `production` serves the built `dist/` and marks the session cookie `Secure`. |

## Hunter accounts

- On first start the server creates accounts for the demo hunters (`sarah.lin`, `marcus.vance`,
  `elena.rostova`) with random passwords, written once to `data/initial-credentials.txt`.
  Hand them out, then delete that file.
- Passwords are stored only as scrypt hashes in `data/users.json`. The `data/` folder is git-ignored.
- Five failed sign-ins lock that username for 15 minutes from the same IP address.
- Hunters change their own password from **Account menu → Change password**.

Create a hunter, or reset a password:

```bash
npm run user:add -- jane.doe "Jane Doe" analyst jane@example.com
```

Roles are `analyst`, `lead` or `admin`. The new password is printed once; set `BLINDSPOT_PASSWORD`
to choose it instead.

## Daily IOC Hunting sheet format

Upload `.xlsx`, `.xls` or `.csv` from **Daily IOC Hunting → Upload latest sheet**. The first sheet with a
**Title** column is used, and the header row may sit below a banner row. Use **Template** to download
a blank sheet.

| Column | Required | Also accepted as |
| --- | --- | --- |
| Title | Yes | Hunt Name, Threat, Intel Name |
| Number | No | No, S.No, Sr No, ID |
| Date | No | Hunt Date |
| Description | No | Details, Summary |
| Threat Category | No | Category, Type (normalised: Malware, Stealer, Ransomware, CVE, ClickFix, APT, Phishing, ...) |
| Query Count | No | No. of Queries (counted from the Queries lines if missing) |
| Results | No | Result, Findings, Outcome |
| Escalation (Task ID / ServiceNow ID) | No | ServiceNow ID, Task ID, Ticket, Incident |
| Queries | No | Query |

- **Duplicates:** a row identical to an existing row in every field is skipped, so the same sheet can be
  uploaded again safely.
- **Results:** "No hits", "None", "Clean" or "N/A" count as no result; anything else counts as a hit.
- **Escalation:** empty, "-", "N/A" or "No" mean not escalated.

## Scripts

| Command | Purpose |
| --- | --- |
| `npm run dev` | Start the Express server with Vite (http://localhost:3000). |
| `npm run build` | Build the front end into `dist/`. |
| `npm start` | Start the server (serves `dist/` when `NODE_ENV=production`). |
| `npm run lint` | Type-check the project (`tsc --noEmit`). |
| `npm run user:add` | Create a hunter or reset a password. |
| `npm run clean` | Delete `dist/`. |

## Project structure

```
server.ts                    Express server: auth routes, /api/ai/* endpoints, Vite / static hosting
server/
  auth.ts                    Users, password hashing, session cookie, login throttling
scripts/
  add-user.ts                CLI to create a hunter or reset a password
data/                        Runtime only, git-ignored: users.json, initial-credentials.txt
src/
  main.tsx                   Entry point
  App.tsx                    Auth gate, app shell, client gate, modals
  index.css                  Design tokens (colors, fonts) and brand animation
  types.ts                   Shared domain types
  app/
    routes.ts                Routes and nav sections (single source of truth)
    useWorkspace.ts          Workspace state and mutations (swap for an API client later)
    AppContext.tsx           useApp(): workspace data and cross-page actions
  components/
    *View.tsx                One file per routed page
    layout/                  NavRail, TopBar, ChangePasswordModal
    overview/                Client overview sections (TacticCoverage)
    reports/                 Hypothesis record form, detail, next-hunt suggestions
    ui/                      Design-system primitives (Button, Card, Stat, Modal, BrandLogo, ClientLogo, ...)
  lib/                       Pure helpers: coverage, routing, persistence, hunt catalog,
                             IOC sheet parsing, phases, PowerPoint export
  services/
    api.ts                   AI endpoint calls
    auth.ts                  Sign-in, sign-out, change password
  utils/                     Scoring calculators and THR document export
  data/                      Demo seed data, ATT&CK catalog, hunt queries, technique hunt guides,
                             IOC demo rows, bundled client logos
legacy/                      Pre-revamp components, kept for reference; not compiled
```

## UI conventions

- Every routed page starts with `<PageHeader>`; card titles use `<CardHeader>` / `<CardTitle>`.
- Use the semantic color tokens in `src/index.css` (`bg-surface`, `text-fg-muted`, `border-border`,
  `bg-accent`, `text-danger-text`, ...). Don't add raw palette colors.
- Gradients are reserved for the brand (logo, wordmark, greeting) and card-title accents.
- Status colors carry meaning: danger = critical / true positive, warning = high / gap,
  success = covered / live.
- Every number shown must be computed from real data. No placeholder metrics or simulated results.
- Features that call AI must tell the user when they fall back to curated content.
- Reference links must be real; AI-suggested links are labelled "unverified".

## Revamp status

| Page | State |
| --- | --- |
| Sign-in, All clients, shell (nav rail, top bar, routing) | Rebuilt |
| Client overview, Hypothesis Record, Daily IOC Hunting, Threat intel, What's New | Rebuilt on the design system |
| Detection rules, ATT&CK coverage, Severity scoring | Rebuilt on the design system |
| Executive decks | PowerPoint export rebuilt; in-app slide preview styling still legacy |
| Create THR modal, Matrix explorer, Clients & telemetry modal | Legacy styling (toned down via transitional palette remap in `index.css`) |
