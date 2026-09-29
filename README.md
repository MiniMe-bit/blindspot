# Blindspot

**Turning threat hunting from scattered documents into a single source of intelligence.**

Blindspot is a threat hunting operations platform for teams that hunt across multiple client
environments. It brings every hypothesis hunt, threat-intel IOC hunt, finding, escalation and detection
outcome into one client-scoped system of record, exposes where each client's detection coverage falls
short, and tells the team what to hunt next. Executive reporting, once assembled by hand, is generated
directly from that record.

*The name reflects the mission: to find what is already there, but not yet visible.*

> **Status:** MVP in progress. Workspace data (clients, records, IOC hunts, rules) is demo data stored in
> the browser (`localStorage`). Hunter accounts are stored on the server. Reset the browser data from
> **Account menu → Reset demo data**.

## Contents

- [Problem statement](#problem-statement)
- [Features](#features)
- [Getting started](#getting-started)
- [Configuration](#configuration)
- [Hunter accounts](#hunter-accounts)
- [Daily IOC Hunting sheet format](#daily-ioc-hunting-sheet-format)
- [Scripts](#scripts)
- [Project structure](#project-structure)
- [UI conventions](#ui-conventions)
- [Revamp status](#revamp-status)

## Problem statement

### Context

Proactive threat hunting is one of the few security activities that finds adversaries before an alert
fires. For a team serving several clients, every engagement produces three streams of work:

1. **Hypothesis-driven hunts**, run in phases of ten, each closing with a verdict: true positive, false
   positive, no result or needs follow-up.
2. **Threat-intelligence IOC hunts**, run daily against newly published indicators and newly exploited
   vulnerabilities, with confirmed hits escalated as incidents.
3. **Executive reporting**, delivered to each client monthly and quarterly.

### The challenge

This work was captured as documents on SharePoint and local drives. Threat intelligence, escalations and
findings existed only inside those reports. The knowledge was recorded, but it was not usable:

> **The team could not answer the questions that matter most (what have we hunted for this client, what
> did we find, what did we escalate, and where are we still blind) without manually reading through every
> report.** Detection gaps were invisible, so the next hunt was chosen from memory rather than evidence.

### Impact

| # | Gap | Operational impact |
| --- | --- | --- |
| 1 | **No system of record.** Hypothesis reports stored as files across SharePoint and local drives. | Retrieving a past hunt, query or finding required searching document by document. |
| 2 | **No outcome visibility.** Verdicts and phase progress buried inside individual reports. | No view of true positives, false positives or phase completion per client. |
| 3 | **Fragmented intelligence.** IOC hunts and their escalations tracked apart from hypothesis hunts. | Threat categories, query volume and incident IDs could not be reviewed together. |
| 4 | **No coverage model.** Hunts not mapped to MITRE ATT&CK. | Untested tactics and techniques, the client's real blind spots, remained hidden. |
| 5 | **Reactive hunt planning.** No structured input for the next hunt. | Priorities depended on individual recall rather than sector threats and coverage gaps. |
| 6 | **Manual report authoring.** Each threat hunt report (THR) written by hand and uploaded separately. | Analyst time diverted from hunting; records and reports drifted apart. |
| 7 | **Untracked detection handoff.** Hunts promoted to detection rules were not followed up. | No visibility into whether a rule was awaiting approval, in production or needed tuning. |
| 8 | **Inconsistent severity.** Findings rated case by case. | Severity differed between hunters and clients, weakening prioritisation. |
| 9 | **Manual executive reporting.** Monthly and quarterly decks rebuilt from raw documents. | Every reporting cycle repeated the same manual data gathering. |

### Objective

Establish **one client-scoped system of record for all threat hunting work**, where each hunt is
captured once and every downstream view is derived from it automatically: outcome tracking, coverage
analysis, hunt planning and executive reporting. The goal is to move the team from reactive record-keeping
to **evidence-driven, proactive hunting**.

### The solution

Blindspot resolves each gap with a dedicated capability built on the same underlying record.

| Gap | Capability | How it is solved |
| --- | --- | --- |
| 1, 2 | **Hypothesis Record** | Every hunt is recorded per client and phase (ten hunts per phase) with its query, ATT&CK techniques, data sources, IOCs and verdict. Instantly searchable and filterable by phase and outcome. |
| 6 | **Create THR** | A complete threat hunt report is generated from a title, summary, queries and findings, and stored as a record in the same step. No separate upload. |
| 3 | **Daily IOC Hunting** | The daily threat-intel hunt sheet is imported directly. Titles, descriptions, threat categories, query counts, results and incident IDs are consolidated in one view, with category weighting and escalation totals. Re-imports are de-duplicated automatically. |
| 4 | **ATT&CK Coverage** | Recorded hunts are mapped to the MITRE ATT&CK matrix, separating hunted from never-hunted techniques. Every gap is paired with the threat groups known to use it, a hunting approach and an example query. |
| 5 | **Threat Intelligence [TTP Hunts]** and **What's New** | Sector-specific threat intelligence and prioritised hunt ideas, each with ready-to-run queries for the client's platform: CrowdStrike, Microsoft Defender, Trend Micro Vision One, Elastic, Sigma and Splunk. |
| 7 | **Detection Rules** | Every hunt promoted to detection keeps a traceable rule record and lifecycle status: testing, pending client review, production, tuning needed or deprecated. |
| 8 | **Severity Scoring** | A consistent, weighted severity from four factors: detection confidence, threat stage (attacker progression), exploitability and business impact. |
| 9 | **Executive Decks** | Monthly and quarterly briefings generated from recorded data, including daily IOC hunting, and exported to PowerPoint in one click. |

### Outcomes

- **Instant recall.** Any hunt, finding, query or escalation for a client is retrieved from one screen,
  without opening a single report.
- **Visible blind spots.** Every catalogued ATT&CK technique is classified as hunted or not hunted, and
  every gap comes with guidance to close it.
- **Evidence-driven planning.** The next hunt is chosen from coverage gaps and sector threat intelligence,
  not memory.
- **Measurable progress.** Phase completion and verdict counts are tracked per client in real time.
- **Reporting without rework.** Threat hunt reports and executive decks are produced from the record
  itself, with every figure computed from logged work.

### Scope

| Delivered in the MVP | Planned beyond the MVP |
| --- | --- |
| Hunter authentication and client-scoped workspaces | Executing queries directly against client SIEM/EDR platforms |
| Hypothesis records with phases, verdicts and THR generation | Automated ingestion of threat-intelligence feeds |
| Daily IOC hunting with sheet import and escalation tracking | Centralised server-side storage of workspace data (currently per browser) |
| ATT&CK coverage analysis, sector TTP hunts, multi-platform queries | Client-facing reporting portal |
| Detection rule tracking, severity scoring, PowerPoint reporting | |

## Features

| Area | What it does |
| --- | --- |
| **Sign-in** | Username/password per hunter, change password from the account menu, 12-hour sessions. |
| **All clients** | Landing page after sign-in. Client pages stay locked until a client is picked. |
| **Client overview** | Client profile, KPI tiles, findings needing attention, ATT&CK coverage by tactic with hunt guides, Threat Intelligence [TTP Hunts] for the client's sector. |
| **Hypothesis Record** | Hunt records per phase (10 hunts each) with outcomes (TP, FP, no result, follow-up), search and filters. New records via the form or document import. |
| **Create THR** | Generates a full threat hunt report from title, summary, queries and findings, and saves it as a hypothesis record. |
| **Daily IOC Hunting** | Imports the daily threat-intel IOC / CVE-check sheet; totals, category weightage, escalations with incident IDs, de-duplicated log. |
| **Threat intel** | Sector-based advisories with TTP hunt packages. |
| **What's New** | Prioritised hunt ideas with queries for CrowdStrike (FQL), Microsoft Defender (KQL), Trend Micro Vision One, Elastic, Sigma and Splunk, plus reference reading. |
| **Detection rules** | Rules promoted from hunts, with status: testing / staging, pending client review, production active, tuning needed, deprecated. |
| **ATT&CK coverage** | Matrix of hunted and never-hunted techniques with ready-made hunts for the gaps. |
| **Severity scoring** | Four-factor severity: detection confidence, threat stage, exploitability, business impact. |
| **Executive decks** | Monthly or quarterly briefings from recorded data, exported as PowerPoint (`.pptx`), including a Daily IOC Hunting slide. |

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
