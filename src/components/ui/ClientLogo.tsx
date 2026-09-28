import React, { useState } from 'react';
import type { ClientOrg } from '../../types';
import { CLIENT_LOGOS } from '../../data/clientLogos';
import { cn } from '../../lib/cn';

const PALETTE = [
  'bg-accent-soft text-accent-text',
  'bg-teal-soft text-teal-text',
  'bg-violet-soft text-violet-text',
  'bg-warning-soft text-warning-text',
  'bg-pink-soft text-pink-text',
  'bg-success-soft text-success-text',
];

const SIZES = {
  sm: { box: 'size-7 rounded-md text-[11px]', pad: 'p-1' },
  md: { box: 'size-10 rounded-lg text-sm', pad: 'p-1.5' },
  lg: { box: 'size-16 rounded-xl text-xl', pad: 'p-2.5' },
  xl: { box: 'size-24 rounded-2xl text-3xl', pad: 'p-4' },
  '2xl': { box: 'size-32 rounded-3xl text-4xl', pad: 'p-5' },
};

type Size = keyof typeof SIZES;

/** Stable color per client so the same client always looks the same. */
const paletteFor = (id: string) => PALETTE[[...id].reduce((a, c) => a + c.charCodeAt(0), 0) % PALETTE.length];

const monogram = (name: string) =>
  name
    .split(/[\s&]+/)
    .filter((w) => /^[A-Za-z0-9]/.test(w))
    .slice(0, 2)
    .map((w) => w[0].toUpperCase())
    .join('');

/**
 * Client logo. Order of preference: bundled brand logo (always available), then a logo URL,
 * then a colored monogram so there is never an empty box.
 */
export const ClientLogo: React.FC<{ client: Pick<ClientOrg, 'id' | 'name' | 'logoSlug' | 'logoUrl'>; size?: Size; className?: string }> = ({
  client,
  size = 'md',
  className,
}) => {
  const [failed, setFailed] = useState(false);
  const s = SIZES[size];
  const brand = client.logoSlug ? CLIENT_LOGOS[client.logoSlug] : undefined;

  if (brand) {
    return (
      <span className={cn('inline-flex shrink-0 items-center justify-center bg-white shadow-sm ring-1 ring-black/5', s.box, s.pad, className)}>
        <svg viewBox="0 0 24 24" role="img" aria-label={`${client.name} logo`} className="size-full" fill={brand.hex}>
          <path d={brand.path} />
        </svg>
      </span>
    );
  }

  if (client.logoUrl && !failed) {
    return (
      <img
        src={client.logoUrl}
        alt={`${client.name} logo`}
        onError={() => setFailed(true)}
        className={cn('shrink-0 bg-white object-contain', s.box, s.pad, className)}
      />
    );
  }

  return (
    <span aria-hidden="true" className={cn('inline-flex shrink-0 items-center justify-center font-semibold tracking-tight', s.box, paletteFor(client.id), className)}>
      {monogram(client.name)}
    </span>
  );
};
