import type { FC } from 'react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { ErrorPanel, Loading } from '../ui/States';
import { api, type ResolvedRef } from '../../lib/api';
import { useApi } from '../../lib/useApi';

/**
 * The policy object graph, shown.
 *
 * It was computed on every assessment and visible nowhere. Rule hygiene,
 * reachability and recertification are all conclusions drawn from it, so a
 * reviewer could see the verdicts but not the reconstruction behind them --
 * and the object count was the only evidence it existed.
 *
 * The point of this panel is the RESOLUTION. A rule says "LAN Subnets"; the
 * graph followed that name to 10.10.0.0/24, and showing the arrow is what lets
 * someone check our work instead of trusting it. A name that did NOT resolve is
 * shown as such, never as an empty set -- an unresolved group rendered blank is
 * how a policy reads as tidier than it is.
 */

/** Colour a resolution state. UNRESOLVED must never look like a clean read. */
function refTone(state: string): string {
  if (state === 'RESOLVED') return 'text-[#32D6A8]';
  if (state === 'UNSUPPORTED') return 'text-[#9B78FF]';
  return 'text-[#F5B82E]';
}

const RefList: FC<{ label: string; refs: ResolvedRef[] }> = ({ label, refs }) => (
  <div className="rounded-lg border border-[rgba(100,150,220,0.14)] p-2.5">
    <span className="text-[10.5px] uppercase tracking-wider text-[var(--color-slate-gray)]">
      {label}
    </span>
    {refs.length === 0 ? (
      <p className="mt-0.5 text-[12px] text-[var(--color-slate-gray)]">—</p>
    ) : (
      refs.slice(0, 6).map((r, i) => (
        <p key={i} className="mt-0.5 font-mono text-[11.5px] leading-relaxed">
          <span className="text-[var(--color-ink-navy)]">{r.name}</span>
          {r.state === 'RESOLVED' ? (
            <span className="text-[var(--color-slate-gray)]">
              {' → '}
              {r.values.slice(0, 3).join(', ') || '(no value)'}
            </span>
          ) : (
            <span className={refTone(r.state)} title={r.detail}>
              {' ['}
              {r.state}
              {']'}
            </span>
          )}
        </p>
      ))
    )}
  </div>
);

export const GraphPanel: FC<{ id: string }> = ({ id }) => {
  const { data, loading, error, reload } = useApi(() => api.graph(id), [id]);

  if (loading) return <Loading label="Reconstructing the policy graph" />;
  if (error) return <ErrorPanel error={error} onRetry={reload} />;
  if (!data) return null;

  const s = data.summary;
  const tiles: [string, string | number][] = [
    ['objects', s.objects.toLocaleString()],
    ['rules', s.rules.toLocaleString()],
    ['zones', s.zones.length],
    [
      `default ${data.default_action_observed ? '(observed)' : '(assumed)'}`,
      data.default_action,
    ],
  ];

  return (
    <div className="space-y-4">
      <Card variant="default" className="p-6">
        <h4 className="mb-1 text-sm font-bold text-[var(--color-ink-navy)]">
          Policy object graph
        </h4>
        <p className="mb-4 text-[12.5px] text-[var(--color-slate-gray)]">
          The reconstruction every other analysis reads. Rule hygiene,
          reachability and recertification are conclusions drawn from this.
        </p>

        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {tiles.map(([label, value]) => (
            <div
              key={label}
              className="rounded-xl border border-[rgba(100,150,220,0.14)] p-3"
            >
              <span className="block text-xl font-bold text-[var(--color-ink-navy)]">
                {value}
              </span>
              <span className="text-[11px] text-[var(--color-slate-gray)]">{label}</span>
            </div>
          ))}
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          {Object.entries(s.by_kind).map(([kind, n]) => (
            <Badge key={kind} variant="outline">
              {kind.replace(/_/g, ' ')} · {n}
            </Badge>
          ))}
        </div>

        {s.untrusted_zones.length > 0 && (
          <p className="mt-3 text-[12px] text-[#AAB8D0]">
            Untrusted zones:{' '}
            <span className="font-mono text-[#F5B82E]">
              {s.untrusted_zones.join(', ')}
            </span>
          </p>
        )}

        {/* An unordered platform has no shadowing, and the absence of shadow
            findings must not be mistaken for a tidy policy. */}
        {!data.ordered && (
          <p className="mt-3 rounded-xl border border-[rgba(45,140,255,0.25)] bg-[rgba(45,140,255,0.06)] p-3 text-[12.5px] text-[#AAB8D0]">
            <strong className="text-[var(--color-ink-navy)]">Unordered platform.</strong> Rules
            here are not evaluated top to bottom, so none can shadow another.
            Shadow and redundancy analysis is suppressed — its absence from the
            findings is correct, not a clean result.
          </p>
        )}
      </Card>

      <Card variant="default" className="overflow-hidden p-0">
        <div className="border-b border-[rgba(100,150,220,0.12)] p-4">
          <h4 className="text-sm font-bold text-[var(--color-ink-navy)]">
            Rules, with references resolved ({data.rules_shown.length} shown)
          </h4>
          <p className="mt-0.5 text-[12px] text-[var(--color-slate-gray)]">
            Every name is followed through to the value it resolves to, so a
            verdict can be checked rather than taken on trust.
          </p>
        </div>
        <div className="max-h-[560px] overflow-y-auto">
          {data.rules_shown.map((r) => (
            <div
              key={r.id}
              className="border-b border-[rgba(100,150,220,0.08)] p-4 last:border-0"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[11px] text-[var(--color-slate-gray)]">#{r.order}</span>
                <Badge variant={r.action === 'allow' ? 'critical' : 'success'}>
                  {r.action}
                </Badge>
                <span className="font-mono text-[12px] text-[var(--color-ink-navy)]">
                  {r.name}
                </span>
                {!r.enabled && <Badge variant="default">disabled</Badge>}
                {r.source_zones.length > 0 && (
                  <span className="text-[11px] text-[var(--color-slate-gray)]">
                    {r.source_zones.join(',')} →{' '}
                    {r.destination_zones.join(',') || 'any'}
                  </span>
                )}
                {r.hit_count !== null && (
                  <span className="text-[11px] text-[var(--color-slate-gray)]">
                    {r.hit_count.toLocaleString()} hits
                  </span>
                )}
              </div>

              <div className="mt-2 grid gap-2 sm:grid-cols-3">
                <RefList label="Source" refs={r.source} />
                <RefList label="Destination" refs={r.destination} />
                <RefList label="Service" refs={r.services} />
              </div>

              {r.undecidable_for_ports && (
                <p className="mt-2 text-[11.5px] text-[#F5B82E]">
                  Cannot decide a port question alone: {r.undecidable_for_ports}
                </p>
              )}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
};
