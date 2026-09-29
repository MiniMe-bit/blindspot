import path from 'path';
import type { NextFunction, Request, Response } from 'express';

/**
 * In development, Vite serves any file under the project root (including via /@fs/ and ?raw),
 * which would expose data/users.json and data/initial-credentials.txt to anyone who can reach the
 * server. This blocks requests that resolve into private folders before Vite sees them.
 */
const ROOT = process.cwd();
const PRIVATE_DIRS = ['data', 'server', 'scripts', 'legacy', 'node_modules/.cache'].map((d) => path.resolve(ROOT, d) + path.sep);
const PRIVATE_FILES = ['server.ts', '.env', 'package-lock.json'].map((f) => path.resolve(ROOT, f));

function resolvesToPrivate(rawUrl: string): boolean {
  let pathname = rawUrl.split('?')[0].split('#')[0];
  try {
    // Decode repeatedly so %252e%252e style double-encoding cannot slip past.
    for (let i = 0; i < 3; i++) {
      const decoded = decodeURIComponent(pathname);
      if (decoded === pathname) break;
      pathname = decoded;
    }
  } catch {
    return true; // malformed encoding: refuse
  }
  pathname = pathname.replace(/\\/g, '/');
  // Windows ignores trailing dots and spaces in names ('data.' opens 'data'), so strip them before
  // comparing. '.' and '..' are kept as-is so parent-directory traversal is still resolved.
  pathname = pathname
    .split('/')
    .map((seg) => (seg === '.' || seg === '..' ? seg : seg.replace(/[. ]+$/, '')))
    .join('/');

  // /@fs/<absolute path> is Vite's direct file-system route.
  const target = pathname.startsWith('/@fs/')
    ? path.resolve(pathname.slice('/@fs'.length).replace(/^\/([A-Za-z]:)/, '$1'))
    : path.resolve(ROOT, '.' + pathname);

  const lower = target.toLowerCase();
  if (PRIVATE_FILES.some((f) => lower === f.toLowerCase())) return true;
  if (/(^|[\\/])\.env(\.|$)/i.test(target)) return true;
  return PRIVATE_DIRS.some((d) => (lower + path.sep).startsWith(d.toLowerCase()));
}

export function blockPrivateFiles(req: Request, res: Response, next: NextFunction) {
  if (req.path.startsWith('/api/')) return next();
  if (resolvesToPrivate(req.originalUrl)) return res.status(404).send('Not found');
  next();
}

/** Baseline browser hardening headers. */
export function securityHeaders(_req: Request, res: Response, next: NextFunction) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY'); // no clickjacking via iframes
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  if (process.env.NODE_ENV === 'production') {
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    );
    res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  }
  next();
}

/** State-changing API calls must be JSON. HTML forms (the usual CSRF vector) can only send form or text bodies. */
export function requireJsonForWrites(req: Request, res: Response, next: NextFunction) {
  if (!req.path.startsWith('/api/') || req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
  if (!req.is('application/json')) return res.status(415).json({ error: 'Requests must be sent as JSON.' });
  next();
}
