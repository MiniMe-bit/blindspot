/**
 * Create a hunter account, or reset the password of an existing one.
 *
 *   npm run user:add -- <username> "<Full Name>" <analyst|lead|admin> [email]
 *
 * The password is read from BLINDSPOT_PASSWORD if set, otherwise a random one is generated
 * and printed once.
 */
import { generatePassword, hashPassword, readUsers, writeUsers, type Role } from '../server/auth';

const [usernameArg, name, roleArg = 'analyst', emailArg] = process.argv.slice(2);
const roles: Role[] = ['analyst', 'lead', 'admin'];

if (!usernameArg || !name || !roles.includes(roleArg as Role)) {
  console.error('Usage: npm run user:add -- <username> "<Full Name>" <analyst|lead|admin> [email]');
  process.exit(1);
}

const username = usernameArg.trim().toLowerCase();
const role = roleArg as Role;
const password = process.env.BLINDSPOT_PASSWORD || generatePassword();
if (password.length < 10) {
  console.error('Password must be at least 10 characters.');
  process.exit(1);
}

const users = readUsers();
const existing = users.find((u) => u.username === username);
const { salt, hash } = hashPassword(password);

if (existing) {
  Object.assign(existing, { name, role, salt, hash, email: emailArg ?? existing.email });
} else {
  users.push({
    id: `user-${Date.now()}`,
    username,
    name,
    email: emailArg ?? '',
    role,
    salt,
    hash,
    createdAt: new Date().toISOString(),
  });
}
writeUsers(users);

console.log(`${existing ? 'Updated' : 'Created'} ${username} (${role}).`);
if (!process.env.BLINDSPOT_PASSWORD) console.log(`Password: ${password}`);
