// @ts-check
import crypto from 'node:crypto';
import bcrypt from 'bcrypt';

/**
 * Passwords are pre-hashed with HMAC-SHA256(pepper) before bcrypt:
 *  - bcrypt silently ignores bytes after 72; the 44-char base64 pre-hash removes that limit,
 *  - the pepper lives in the environment, so a stolen database alone cannot be brute-forced.
 * Changing AUTHZ_PEPPER later invalidates every stored password - set it once.
 */
function prehash(/** @type {string} */ password, /** @type {string} */ pepper) {
  return crypto.createHmac('sha256', pepper || 'jwt-rbac-engine').update(password.normalize('NFKC'), 'utf8').digest('base64');
}

/** @param {string} password @param {{rounds:number, pepper:string}} opts */
export async function hashPassword(password, opts) {
  return bcrypt.hash(prehash(password, opts.pepper), opts.rounds);
}

/**
 * @param {string} password @param {string|null|undefined} hash @param {{rounds:number, pepper:string}} opts
 * @returns {Promise<{ok:boolean, needsRehash:boolean}>}
 */
export async function verifyPassword(password, hash, opts) {
  // Always run one bcrypt compare, even for unknown users, so response time does not reveal which emails exist.
  const target = hash || (await dummyHash(opts));
  const ok = await bcrypt.compare(prehash(password, opts.pepper), target);
  const rounds = hash ? bcrypt.getRounds(hash) : opts.rounds;
  return { ok: Boolean(hash) && ok, needsRehash: Boolean(hash) && ok && rounds !== opts.rounds };
}

/** @type {Map<number, Promise<string>>} */
const dummies = new Map();
function dummyHash(/** @type {{rounds:number, pepper:string}} */ opts) {
  if (!dummies.has(opts.rounds)) dummies.set(opts.rounds, bcrypt.hash(crypto.randomBytes(16).toString('hex'), opts.rounds));
  return /** @type {Promise<string>} */ (dummies.get(opts.rounds));
}

// Short list of the most-used leaked passwords (and patterns built on them).
const COMMON = new Set(
  `password password1 password123 passw0rd 123456 1234567 12345678 123456789 1234567890 12345678910 qwerty qwerty123 qwertyuiop
  111111 000000 abc123 abcd1234 iloveyou admin admin123 administrator welcome welcome1 welcome123 letmein monkey dragon
  football baseball master sunshine princess shadow superman michael trustno1 starwars login secret changeme changeme123
  azerty asdfghjkl zxcvbnm 1q2w3e4r 1qaz2wsx qazwsx q1w2e3r4 p@ssw0rd p@ssword pa$$word test1234 testtest guest
  default summer2024 winter2024 spring2025 summer2025 autumn2025 winter2025 company123 office123 hello123 secret123`
    .split(/\s+/)
    .filter(Boolean),
);

/**
 * @param {string} password
 * @param {{minLength:number, maxLength:number, blockCommon:boolean, requireClasses:number}} policy
 * @param {{email?:string, name?:string}} [context]
 * @returns {string[]} problems (empty = acceptable)
 */
export function checkPasswordPolicy(password, policy, context = {}) {
  const problems = [];
  if (typeof password !== 'string') return ['password is required'];
  const len = [...password].length;
  if (len < policy.minLength) problems.push(`must be at least ${policy.minLength} characters`);
  if (len > policy.maxLength) problems.push(`must be at most ${policy.maxLength} characters`);
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  if (classes < policy.requireClasses)
    problems.push(`must mix at least ${policy.requireClasses} of: lowercase, uppercase, digits, symbols`);
  const lower = password.toLowerCase();
  if (policy.blockCommon) {
    const stripped = lower.replace(/[\d!@#$%^&*._-]+$/, '');
    if (COMMON.has(lower) || COMMON.has(stripped)) problems.push('is a commonly used password');
    if (/^(.)\1+$/.test(password)) problems.push('is one repeated character');
  }
  const local = context.email?.split('@')[0]?.toLowerCase();
  if (local && local.length >= 4 && lower.includes(local)) problems.push('must not contain your email name');
  return problems;
}

/** Strong random password for invites / generated admin accounts (no ambiguous characters). */
export function generatePassword(length = 20) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%*-_';
  const out = [];
  while (out.length < length) {
    const b = crypto.randomBytes(1)[0];
    if (b < 256 - (256 % alphabet.length)) out.push(alphabet[b % alphabet.length]);
  }
  // guarantee at least one digit and one symbol
  out[0] = '23456789'[crypto.randomInt(8)];
  out[1] = '!@#%*-_'[crypto.randomInt(7)];
  for (let i = out.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out.join('');
}
