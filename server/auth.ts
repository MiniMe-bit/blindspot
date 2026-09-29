import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import type { NextFunction, Request, Response } from 'express';

/**
 * Username/password auth for hunters.
 *
 * - Users live in data/users.json with scrypt password hashes (never plaintext).
 * - Sessions are an HMAC-signed, HttpOnly cookie; no server-side session store needed.
 * - Admins add hunters, reset passwords and clear lockouts in the app (Account menu → Manage hunters)
 *   or with: npm run user:add -- <username> "<Full Name>" <analyst|lead|admin>
 * - Temporary passwords (new hunter / reset) must be changed at the next sign-in.
 */

export type Role = 'analyst' | 'lead' | 'admin';

export interface StoredUser {
  id: string;
  username: string;
  name: string;
  email: string;
  role: Role;
  salt: string;
  hash: string;
  createdAt: string;
  /** Set for admin-issued temporary passwords; the hunter must pick a new one before using the app. */
  mustChangePassword?: boolean;
  /** Bumped on every password change or reset so sessions issued before it stop working. */
  tokenVersion?: number;
}

export type PublicUser = Omit<StoredUser, 'salt' | 'hash' | 'createdAt' | 'tokenVersion'>;

const DATA_DIR = path.resolve(process.cwd(), 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const INITIAL_CREDENTIALS_FILE = path.join(DATA_DIR, 'initial-credentials.txt');

const COOKIE = 'bs_session';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // one working shift

// Resolved on first use, not at import time: server.ts loads .env after its imports are evaluated.
let secret: string | undefined;
function getSecret() {
  if (secret) return secret;
  secret = process.env.SESSION_SECRET;
  if (!secret) {
    console.warn('[auth] SESSION_SECRET is not set: using a random secret, so everyone is signed out when the server restarts.');
    secret = crypto.randomBytes(32).toString('hex');
  }
  return secret;
}

// ---------------------------------------------------------------------------
// Password hashing
// ---------------------------------------------------------------------------

export function hashPassword(password: string, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

/** Hash checked when the username does not exist, so sign-in takes the same time either way (no username probing). */
const DUMMY = hashPassword(crypto.randomBytes(16).toString('hex'));

function verifyPassword(password: string, user: StoredUser): boolean {
  const candidate = crypto.scryptSync(password, user.salt, 64);
  const expected = Buffer.from(user.hash, 'hex');
  return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

// ---------------------------------------------------------------------------
// User store
// ---------------------------------------------------------------------------

export function readUsers(): StoredUser[] {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')) as StoredUser[];
  } catch {
    return [];
  }
}

export function writeUsers(users: StoredUser[]) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

export const toPublic = ({ salt, hash, createdAt, tokenVersion, ...rest }: StoredUser): PublicUser => rest;

/** Readable random password, e.g. "hunt-7f3a-92c1-e0b4". */
export const generatePassword = () => `hunt-${crypto.randomBytes(6).toString('hex').match(/.{4}/g)!.join('-')}`;

/**
 * First run only: create accounts for the demo hunters (ids match the seed data) with random
 * passwords, written once to data/initial-credentials.txt. Nothing happens if users already exist.
 */
export function ensureInitialUsers() {
  if (readUsers().length) return;

  const seed: Array<Pick<StoredUser, 'id' | 'username' | 'name' | 'email' | 'role'>> = [
    { id: 'user-1', username: 'sarah.lin', name: 'Sarah Lin', email: 'sarah.lin@blindspot-threats.io', role: 'analyst' },
    { id: 'user-2', username: 'marcus.vance', name: 'Marcus Vance', email: 'marcus.vance@blindspot-threats.io', role: 'lead' },
    { id: 'user-3', username: 'elena.rostova', name: 'Elena Rostova', email: 'elena.rostova@blindspot-threats.io', role: 'admin' },
  ];

  const lines: string[] = [];
  const users = seed.map((u) => {
    const password = generatePassword();
    lines.push(`${u.username.padEnd(16)} ${password}   (${u.role})`);
    return { ...u, ...hashPassword(password), createdAt: new Date().toISOString(), mustChangePassword: true, tokenVersion: 0 };
  });
  writeUsers(users);
  fs.writeFileSync(
    INITIAL_CREDENTIALS_FILE,
    `Blindspot initial hunter accounts (generated ${new Date().toISOString()}).\n` +
      `These are temporary passwords: each hunter must change theirs at first sign-in.\n` +
      `Share each password with its owner, then delete this file.\n\n` +
      lines.join('\n') +
      '\n',
  );
  console.log(`[auth] Created ${users.length} hunter accounts. Initial passwords: ${INITIAL_CREDENTIALS_FILE}`);
}

// ---------------------------------------------------------------------------
// Session cookie
// ---------------------------------------------------------------------------

const sign = (value: string) => crypto.createHmac('sha256', getSecret()).update(value).digest('base64url');

function createToken(user: StoredUser) {
  const payload = Buffer.from(JSON.stringify({ uid: user.id, tv: user.tokenVersion ?? 0, exp: Date.now() + SESSION_TTL_MS })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}

function readToken(token: string | undefined): { uid: string; tv: number } | null {
  if (!token) return null;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return null;
  const expected = Buffer.from(sign(payload));
  const given = Buffer.from(sig);
  if (expected.length !== given.length || !crypto.timingSafeEqual(expected, given)) return null;
  try {
    const { uid, tv, exp } = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (typeof uid !== 'string' || typeof exp !== 'number' || exp <= Date.now()) return null;
    return { uid, tv: typeof tv === 'number' ? tv : 0 };
  } catch {
    return null;
  }
}

function getCookie(req: Request, name: string) {
  const header = req.headers.cookie ?? '';
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return undefined;
}

function setSessionCookie(res: Response, token: string, maxAgeMs: number) {
  const attrs = [`${COOKIE}=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${Math.floor(maxAgeMs / 1000)}`];
  if (process.env.NODE_ENV === 'production') attrs.push('Secure');
  res.setHeader('Set-Cookie', attrs.join('; '));
}

export function sessionUser(req: Request): PublicUser | null {
  const token = readToken(getCookie(req, COOKIE));
  if (!token) return null;
  const user = readUsers().find((u) => u.id === token.uid);
  // A password change or admin reset bumps tokenVersion and ends older sessions.
  if (!user || (user.tokenVersion ?? 0) !== token.tv) return null;
  return toPublic(user);
}

// ---------------------------------------------------------------------------
// Login throttling: 5 failed attempts per IP+username per 15 minutes
// ---------------------------------------------------------------------------

const FAIL_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILS = 5;
/** Per-IP cap across all usernames, so one address cannot spray passwords over every account. */
const MAX_FAILS_PER_IP = 20;
/** Keys: "<ip>|<username>", "<ip>|<username>|change" and "<ip>|*" (per-address cap). */
const failures = new Map<string, { count: number; first: number }>();

function isLocked(key: string, max = MAX_FAILS) {
  const f = failures.get(key);
  if (!f) return false;
  if (Date.now() - f.first > FAIL_WINDOW_MS) {
    failures.delete(key);
    return false;
  }
  return f.count >= max;
}

/** Drop expired entries so the table cannot grow without bound under a flood of random usernames. */
function sweepFailures() {
  const now = Date.now();
  for (const [k, f] of failures) if (now - f.first > FAIL_WINDOW_MS) failures.delete(k);
}
setInterval(sweepFailures, FAIL_WINDOW_MS).unref();

function recordFailure(key: string) {
  if (failures.size > 50_000) sweepFailures();
  const f = failures.get(key);
  if (!f || Date.now() - f.first > FAIL_WINDOW_MS) failures.set(key, { count: 1, first: Date.now() });
  else f.count += 1;
}

/** Usernames with an active sign-in or change-password lockout, from any address. */
function lockedUsernames(): Set<string> {
  const locked = new Set<string>();
  for (const key of [...failures.keys()]) {
    const username = key.split('|')[1];
    if (username && username !== '*' && isLocked(key)) locked.add(username);
  }
  return locked;
}

/** Clear a hunter's lockouts, plus per-address caps so a shared office IP is not still blocked. */
function clearLockouts(username: string) {
  for (const key of [...failures.keys()]) {
    const u = key.split('|')[1];
    if (u === username || u === '*') failures.delete(key);
  }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

export function loginHandler(req: Request, res: Response) {
  const username = String(req.body?.username ?? '').trim().toLowerCase();
  const password = String(req.body?.password ?? '');
  if (!username || !password) return res.status(400).json({ error: 'Enter your username and password.' });

  const key = `${req.ip}|${username}`;
  const ipKey = `${req.ip}|*`;
  if (isLocked(key) || isLocked(ipKey, MAX_FAILS_PER_IP)) {
    return res.status(429).json({ error: 'Too many failed attempts. Wait 15 minutes, or ask an admin to unlock your account.' });
  }

  const user = readUsers().find((u) => u.username.toLowerCase() === username);
  // Always run one scrypt check, even for unknown usernames, so response time does not reveal who exists.
  const ok = verifyPassword(password, user ?? ({ ...DUMMY } as StoredUser)) && Boolean(user);
  if (!user || !ok) {
    recordFailure(key);
    recordFailure(ipKey);
    return res.status(401).json({ error: 'Username or password is incorrect.' });
  }

  failures.delete(key);
  setSessionCookie(res, createToken(user), SESSION_TTL_MS);
  return res.json({ user: toPublic(user) });
}

export function changePasswordHandler(req: Request, res: Response) {
  const current = sessionUser(req);
  if (!current) return res.status(401).json({ error: 'Not signed in.' });

  const currentPassword = String(req.body?.currentPassword ?? '');
  const newPassword = String(req.body?.newPassword ?? '');
  if (newPassword.length < 10) return res.status(400).json({ error: 'The new password must be at least 10 characters.' });
  if (newPassword === currentPassword) return res.status(400).json({ error: 'The new password must be different from the current one.' });

  // Same throttle as sign-in, so this endpoint can't be used to guess the current password.
  const key = `${req.ip}|${current.username}|change`;
  if (isLocked(key)) return res.status(429).json({ error: 'Too many failed attempts. Wait 15 minutes and try again.' });

  const users = readUsers();
  const user = users.find((u) => u.id === current.id);
  if (!user || !verifyPassword(currentPassword, user)) {
    recordFailure(key);
    return res.status(400).json({ error: 'Your current password is incorrect.' });
  }

  failures.delete(key);
  Object.assign(user, hashPassword(newPassword), { mustChangePassword: false, tokenVersion: (user.tokenVersion ?? 0) + 1 });
  writeUsers(users);
  // Other sessions for this hunter end; this one continues with a fresh cookie.
  setSessionCookie(res, createToken(user), SESSION_TTL_MS);
  return res.json({ ok: true, user: toPublic(user) });
}

export function logoutHandler(_req: Request, res: Response) {
  setSessionCookie(res, '', 0);
  res.json({ ok: true });
}

export function meHandler(req: Request, res: Response) {
  const user = sessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not signed in.' });
  return res.json({ user });
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const user = sessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not signed in.' });
  if (user.mustChangePassword) return res.status(403).json({ error: 'Change your temporary password to continue.' });
  next();
}

// ---------------------------------------------------------------------------
// Admin: manage hunters
// ---------------------------------------------------------------------------

const ROLES: Role[] = ['analyst', 'lead', 'admin'];
const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{1,31}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const user = sessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not signed in.' });
  if (user.mustChangePassword) return res.status(403).json({ error: 'Change your temporary password to continue.' });
  if (user.role !== 'admin') return res.status(403).json({ error: 'Only admins can manage hunters.' });
  next();
}

export function listUsersHandler(_req: Request, res: Response) {
  const locked = lockedUsernames();
  const users = readUsers().map((u) => ({ ...toPublic(u), createdAt: u.createdAt, locked: locked.has(u.username) }));
  res.json({ users });
}

export function createUserHandler(req: Request, res: Response) {
  const username = String(req.body?.username ?? '').trim().toLowerCase();
  const name = String(req.body?.name ?? '').trim();
  const email = String(req.body?.email ?? '').trim();
  const role = String(req.body?.role ?? 'analyst') as Role;

  if (!USERNAME_RE.test(username)) return res.status(400).json({ error: 'Username must be 2–32 characters: letters, numbers, dots, dashes or underscores.' });
  if (!name || name.length > 80) return res.status(400).json({ error: "Enter the hunter's full name." });
  if (!ROLES.includes(role)) return res.status(400).json({ error: 'Role must be analyst, lead or admin.' });
  if (email && !EMAIL_RE.test(email)) return res.status(400).json({ error: 'Enter a valid email address or leave it empty.' });

  const users = readUsers();
  if (users.some((u) => u.username === username)) return res.status(409).json({ error: `A hunter named "${username}" already exists.` });

  const temporaryPassword = generatePassword();
  const user: StoredUser = {
    id: `user-${crypto.randomUUID()}`,
    username,
    name,
    email,
    role,
    ...hashPassword(temporaryPassword),
    createdAt: new Date().toISOString(),
    mustChangePassword: true,
    tokenVersion: 0,
  };
  users.push(user);
  writeUsers(users);
  res.json({ user: toPublic(user), temporaryPassword });
}

export function resetPasswordHandler(req: Request, res: Response) {
  const users = readUsers();
  const user = users.find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Hunter not found.' });

  const temporaryPassword = generatePassword();
  // New temporary password, forced change at next sign-in, and every existing session for this hunter ends.
  Object.assign(user, hashPassword(temporaryPassword), { mustChangePassword: true, tokenVersion: (user.tokenVersion ?? 0) + 1 });
  writeUsers(users);
  clearLockouts(user.username);
  res.json({ user: toPublic(user), temporaryPassword });
}

export function unlockHandler(req: Request, res: Response) {
  const user = readUsers().find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Hunter not found.' });
  clearLockouts(user.username);
  res.json({ ok: true });
}
