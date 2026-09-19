import { type FC } from 'react';
import { Bug, KeyRound, Wifi } from 'lucide-react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { ErrorPanel, Loading } from '../ui/States';
import {
  api,
  type ExtendedDomain,
  type ExtendedEvidence,
  type ExtendedFinding,
  type ResultState,
} from '../../lib/api';
import { useApi } from '../../lib/useApi';

/**
 * VPN, wireless and known-vulnerability checks.
 *
 * Shown beside the compliance score and never inside it: adding them to the
 * 88-control catalogue would move every device's score, including results
 * already reported. The scope line at the top says so, because a reader who
 * sees nine CVEs and an unchanged score will otherwise assume a bug.
 */

const ORDER = ['cve', 'vpn', 'wireless'] as const;

const META: Record<string, { label: string; icon: typeof Bug }> = {
  cve: { label: 'Known vulnerabilities', icon: Bug },
  vpn: { label: 'IPsec VPN', icon: KeyRound },
  wireless: { label: 'Wireless', icon: Wifi },
};

const STATE_VARIANT: Record<
  ResultState,
  'success' | 'critical' | 'warning' | 'default' | 'outline' | 'info'
> = {
  PASS: 'success',
  FAIL: 'critical',
  PARTIAL: 'warning',
  NOT_APPLICABLE: 'default',
  UNKNOWN: 'outline',
  MANUAL_REVIEW: 'info',
  ERROR: 'critical',
};

// Failures first: the reader came for what is wrong. Passes and exclusions are
// counted, not listed, so they cannot bury a finding.
const LISTED: ResultState[] = ['FAIL', 'PARTIAL', 'MANUAL_REVIEW', 'UNKNOWN'];

function locate(e: ExtendedEvidence): string {
  if (e.line !== null) return `line ${e.line}`;
  const m = e.record?.match(/^setting\[(\d+)\]$/);
  return m ? `setting ${m[1]}` : (e.record ?? 'no position');
}

export const ExtendedPanel: FC<{ id: string }> = ({ id }) => {
  const { data, loading, error, reload } = useApi(() => api.extended(id), [id]);

  if (loading) return <Loading label="Running extended checks" />;
  if (error) return <ErrorPanel error={error} onRetry={reload} />;
  if (!data) return null;

  return (
    <div className="space-y-4">
      <p className="rounded-2xl border border-[rgba(100,150,220,0.14)] bg-[rgba(14,27,50,0.4)] p-3 text-[12.5px] text-[#AAB8D0]">
        {data.scope}
      </p>
      {ORDER.filter((k) => data.domains[k]).map((k) => (
        <DomainCard key={k} name={k} d={data.domains[k]} />
      ))}
    </div>
  );
};

const DomainCard: FC<{ name: string; d: ExtendedDomain }> = ({ name, d }) => {
  const meta = META[name] ?? { label: name, icon: Bug };
  const Icon = meta.icon;
  const listed = d.findings.filter((f) => LISTED.includes(f.state));
  const fixture = d.validated_on.toLowerCase().includes('fixture');

  return (
    <Card variant="default" className="p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[rgba(22,119,255,0.14)] text-[#2D8CFF]">
            <Icon className="h-4 w-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-[var(--color-ink-navy)]">{meta.label}</h3>
            {d.validated_on && d.validated_on !== 'n/a' && (
              <span className="text-[11px] text-[var(--color-slate-gray)]">
                validated on {d.validated_on}
              </span>
            )}
          </div>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {d.present === null && <Badge variant="outline">could not tell</Badge>}
          {d.present === false && <Badge variant="default">none present</Badge>}
          {fixture && <Badge variant="warning">fixture, not a real export</Badge>}
          {Object.entries(d.counts).map(([s, n]) => (
            <Badge key={s} variant={STATE_VARIANT[s as ResultState] ?? 'default'}>
              {n} {s.replace('_', ' ').toLowerCase()}
            </Badge>
          ))}
        </div>
      </div>

      <p className="mt-3 text-[13px] leading-relaxed text-[var(--color-ink-navy)]">{d.summary}</p>

      {name === 'cve' && d.inventory.length > 0 && <CveTable rows={d.inventory} />}
      {name === 'vpn' && d.inventory.length > 0 && <VpnTable rows={d.inventory} />}

      {listed.length > 0 && (
        <div className="mt-4 space-y-2">
          {listed.map((f, i) => (
            <FindingRow key={`${f.check_id}-${f.scope}-${i}`} f={f} />
          ))}
        </div>
      )}

      {d.notes.length > 0 && (
        <ul className="mt-4 space-y-1 text-[11.5px] leading-relaxed text-[var(--color-slate-gray)]">
          {d.notes.map((n) => (
            <li key={n}>· {n}</li>
          ))}
        </ul>
      )}
    </Card>
  );
};

const FindingRow: FC<{ f: ExtendedFinding }> = ({ f }) => (
  <div className="rounded-xl border border-[rgba(100,150,220,0.14)] p-3">
    <div className="flex flex-wrap items-center gap-2">
      <Badge variant={STATE_VARIANT[f.state]}>{f.state.replace('_', ' ')}</Badge>
      <span className="text-[11px] uppercase tracking-wider text-[var(--color-slate-gray)]">
        {f.severity}
      </span>
      <span className="font-mono text-[11px] text-[var(--color-slate-gray)]">{f.check_id}</span>
      <span className="text-[12.5px] font-semibold text-[var(--color-ink-navy)]">{f.scope}</span>
    </div>
    <p className="mt-1 text-[12.5px] text-[#AAB8D0]">
      <span className="text-[var(--color-ink-navy)]">{f.title}.</span> {f.reason}
    </p>
    {f.evidence.slice(0, 3).map((e, i) => (
      <div
        key={i}
        className="mt-1.5 flex items-baseline gap-2 rounded-lg bg-[rgba(5,11,24,0.8)] px-2 py-1"
      >
        <span className="shrink-0 font-mono text-[10.5px] text-[var(--color-slate-gray)]">
          {locate(e)}
        </span>
        <code className="min-w-0 break-all font-mono text-[11.5px] text-[var(--color-ink-navy)]">
          {e.raw}
        </code>
      </div>
    ))}
    {(f.attack.length > 0 || f.nist_800_53.length > 0) && (
      <div className="mt-2 flex flex-wrap gap-1.5">
        {f.attack.map((t) => (
          <span
            key={t.id}
            title={t.why}
            className="rounded-full border border-[rgba(229,72,77,0.25)] px-2 py-0.5 font-mono text-[10.5px] text-[#E5484D]"
          >
            ATT&amp;CK {t.id} · {t.name}
          </span>
        ))}
        {f.nist_800_53.map((n) => (
          <span
            key={n}
            className="rounded-full border border-[rgba(100,150,220,0.2)] px-2 py-0.5 font-mono text-[10.5px] text-[#AAB8D0]"
          >
            NIST {n}
          </span>
        ))}
      </div>
    )}
  </div>
);

const CveTable: FC<{ rows: Record<string, unknown>[] }> = ({ rows }) => (
  <div className="mt-4 overflow-x-auto">
    <table className="w-full text-left text-[12px]">
      <thead className="text-[10.5px] uppercase tracking-wider text-[var(--color-slate-gray)]">
        <tr>
          <th className="py-1.5 pr-3">CVE</th>
          <th className="py-1.5 pr-3">CVSS</th>
          <th className="py-1.5 pr-3">Exploited</th>
          <th className="py-1.5">Why it matches this device</th>
        </tr>
      </thead>
      <tbody className="text-[var(--color-ink-navy)]">
        {rows.map((r) => {
          const refs = (r.references as string[] | undefined) ?? [];
          return (
            <tr key={String(r.id)} className="border-t border-[rgba(100,150,220,0.1)]">
              <td className="py-1.5 pr-3 font-mono">
                {refs[0] ? (
                  <a href={refs[0]} target="_blank" rel="noreferrer" className="text-[#2D8CFF] hover:underline">
                    {String(r.id)}
                  </a>
                ) : (
                  String(r.id)
                )}
              </td>
              <td className="py-1.5 pr-3">{String(r.cvss ?? '—')}</td>
              <td className="py-1.5 pr-3">
                {r.known_exploited ? (
                  <Badge variant="critical">CISA KEV</Badge>
                ) : (
                  <span className="text-[var(--color-slate-gray)]">not listed</span>
                )}
              </td>
              <td className="py-1.5 font-mono text-[11px] text-[#AAB8D0]">
                {String(r.matched_on)}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  </div>
);

const VpnTable: FC<{ rows: Record<string, unknown>[] }> = ({ rows }) => {
  const yes = (v: unknown) =>
    v === true ? '✓' : v === false ? '✗' : '—';
  return (
    <div className="mt-4 overflow-x-auto">
      <table className="w-full text-left text-[12px]">
        <thead className="text-[10.5px] uppercase tracking-wider text-[var(--color-slate-gray)]">
          <tr>
            <th className="py-1.5 pr-3">Tunnel</th>
            <th className="py-1.5 pr-3">Enabled</th>
            <th className="py-1.5 pr-3">PFS</th>
            <th className="py-1.5 pr-3">Anti-replay</th>
            <th className="py-1.5 pr-3">IKE / IPsec lifetime</th>
            <th className="py-1.5">Algorithms (vendor codes)</th>
          </tr>
        </thead>
        <tbody className="text-[var(--color-ink-navy)]">
          {rows.map((r) => (
            <tr key={String(r.name)} className="border-t border-[rgba(100,150,220,0.1)]">
              <td className="py-1.5 pr-3">{String(r.name)}</td>
              <td className="py-1.5 pr-3">{yes(r.enabled)}</td>
              <td className={`py-1.5 pr-3 ${r.enabled !== false && r.pfs === false ? 'text-[#E5484D]' : ''}`}>
                {yes(r.pfs)}
              </td>
              <td className={`py-1.5 pr-3 ${r.enabled !== false && r.anti_replay === false ? 'text-[#E5484D]' : ''}`}>
                {yes(r.anti_replay)}
              </td>
              <td className="py-1.5 pr-3 font-mono text-[11px]">
                {String(r.ike_lifetime_s ?? '—')}s / {String(r.ipsec_lifetime_s ?? '—')}s
              </td>
              <td className="py-1.5 font-mono text-[10.5px] text-[var(--color-slate-gray)]">
                {Object.entries((r.algorithms_raw as Record<string, string>) ?? {})
                  .map(([k, v]) => `${k.replace('ipsec', '')}=${v}`)
                  .join(' ')}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
