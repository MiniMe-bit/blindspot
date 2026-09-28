/** Join class names, skipping falsy values. */
export function cn(...classes: Array<string | false | null | undefined>): string {
  return classes.filter(Boolean).join(' ');
}

/** Which "slot" a utility fills, for the few groups our primitives let callers override. */
const slotOf = (c: string): string | null => {
  if (c.includes(':')) return null; // variant classes (hover:, sm:) never replace a base class
  const m = c.match(/^(h|w|pl|pr|pt|pb|py|px)-/);
  if (m) return m[1];
  if (/^text-(xs|sm|base|lg|xl|\d?xl|\[\d)/.test(c)) return 'text-size';
  return null;
};

/**
 * Base classes + caller classes, where a caller class drops any base class in the same slot
 * (height, width, padding side, font size). Tailwind resolves conflicts by stylesheet order,
 * not attribute order, so without this `h-8` might not beat a base `h-9`.
 */
export function mergeDefaults(base: string, extra?: string): string {
  const extras = (extra ?? '').split(/\s+/).filter(Boolean);
  const overridden = new Set(extras.map(slotOf).filter(Boolean));
  const kept = base.split(/\s+/).filter((c) => c && !overridden.has(slotOf(c)));
  return [...kept, ...extras].join(' ');
}
