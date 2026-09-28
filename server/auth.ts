import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import type { NextFunction, Request, Response } from 'express';

/**
 * Username/password auth for hunters.
 *
 * - Users live in data/users.json with scrypt password hashes (never plaintext).
 * - Sessions are an HMAC-signed, HttpOnly cookie; no server-side session store needed.
 * - Add or reset a user with: npm run user:add -- <username> "<Full Name>" <analyst|lead|admin>
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
}

export type PublicUser = Omit<StoredUser, 'salt' | 'hash' | 'createdAt'>;

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

export const toPublic = ({ salt, hash, createdAt, ...rest }: StoredUser): PublicUser => rest;

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
    return { ...u, ...hashPassword(password), createdAt: new Date().toISOString() };
  });
  writeUsers(users);
  fs.writeFileSync(
    INITIAL_CREDENTIALS_FILE,
    `Blindspot initial hunter accounts (generated ${new Date().toISOString()}).\n` +
      `Share each password with its owner, then delete this file.\n` +
      `Reset a password with: npm run user:add -- <username> "<Full Name>" <role>\n\n` +
      lines.join('\n') +
      '\n',
  );
  console.log(`[auth] Created ${users.length} hunter accounts. Initial passwords: ${INITIAL_CREDENTIALS_FILE}`);
}

// ---------------------------------------------------------------------------
// Session cookie
// ---------------------------------------------------------------------------

const sign = (value: string) => crypto.createHmac('sha256', getSecret()).update(value).digest('base64url');

function createToken(userId: string) {
  const payload = Buffer.from(JSON.stringify({ uid: userId, exp: Date.now() + SESSION_TTL_MS })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}

function readToken(token: string | undefined): string | null {
  if (!token) return null;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return null;
  const expected = Buffer.from(sign(payload));
  const given = Buffer.from(sig);
  if (expected.length !== given.length || !crypto.timingSafeEqual(expected, given)) return null;
  try {
    const { uid, exp } = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return typeof uid === 'string' && typeof exp === 'number' && exp > Date.now() ? uid : null;
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
  const uid = readToken(getCookie(req, COOKIE));
  if (!uid) return null;
  const user = readUsers().find((u) => u.id === uid);
  return user ? toPublic(user) : null;
}

// ---------------------------------------------------------------------------
// Login throttling: 5 failed attempts per IP+username per 15 minutes
// ---------------------------------------------------------------------------

const FAIL_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILS = 5;
const failures = new Map<string, { count: number; first: number }>();

function isLocked(key: string) {
  const f = failures.get(key);
  if (!f) return false;
  if (Date.now() - f.first > FAIL_WINDOW_MS) {
    failures.delete(key);
    return false;
  }
  return f.count >= MAX_FAILS;
}

function recordFailure(key: string) {
  const f = failures.get(key);
  if (!f || Date.now() - f.first > FAIL_WINDOW_MS) failures.set(key, { count: 1, first: Date.now() });
  else f.count += 1;
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

export function loginHandler(req: Request, res: Response) {
  const username = String(req.body?.username ?? '').trim().toLowerCase();
  const password = String(req.body?.password ?? '');
  if (!username || !password) return res.status(400).json({ error: 'Enter your username and password.' });

  const key = `${req.ip}|${username}`;
  if (isLocked(key)) return res.status(429).json({ error: 'Too many failed attempts. Wait 15 minutes and try again.' });

  const user = readUsers().find((u) => u.username.toLowerCase() === username);
  if (!user || !verifyPassword(password, user)) {
    recordFailure(key);
    return res.status(401).json({ error: 'Username or password is incorrect.' });
  }

  failures.delete(key);
  setSessionCookie(res, createToken(user.id), SESSION_TTL_MS);
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
  Object.assign(user, hashPassword(newPassword));
  writeUsers(users);
  return res.json({ ok: true });
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
  if (!sessionUser(req)) return res.status(401).json({ error: 'Not signed in.' });
  next();
}
