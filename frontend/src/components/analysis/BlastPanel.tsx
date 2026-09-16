import { useMemo, useState, type FC } from 'react';
import { Crosshair, FlaskConical } from 'lucide-react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { ErrorPanel, Loading } from '../ui/States';
import {
  api,
  ApiError,
  type BlastResponse,
  type WhatIfResponse,
} from '../../lib/api';
import { useApi } from '../../lib/useApi';

/**
 * Blast radius: if this zone is compromised, what else can be reached?
 *
 * Two honesty rules are rendered, not just computed:
 *   - LATENT. When nothing sits in the origin zone (no interface, no access
 *     point), the paths are policy exposure, not live reachability. The banner
 *     says so instead of letting "guest Wi-Fi compromised" read as a live risk
 *     on a device with no guest Wi-Fi.
 *   - UNPROVEN IS NOT ABSENT. Undecidable probes are shown per zone, never
 *     silently counted as blocked.
 *
 * "Simulate closing" runs the same what-if engine the score uses, on a copy.
 */
export const BlastPanel: FC<{ id: string }> = ({ id }) => {
  const zones = useApi(() => api.zones(id), [id]);
  const [zone, setZone] = useState('');
  const [result, setResult] = useState<BlastResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);

  // Default to the most instructive starting point: an untrusted zone that is
  // not the internet itself (WLAN on a SonicWall), else the first source zone.
  const defaultZone = useMemo(() => {
    const z = zones.data;
    if (!z) return '';
    const inside = z.untrusted.find((u) => u.toUpperCase() !== 'WAN');
    return inside ?? z.untrusted[0] ?? z.source_zones[0] ?? '';
  }, [zones.data]);

  // Derived during render: the user's pick if they made one, else the default.
  const selected = zone || defaultZone;

  const run = async (z: string) => {
    setBusy(true);
    setErr(null);
    try {
      setResult(await api.blastRadius(id, z));
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  };

  if (zones.loading) return <Loading label="Reading zones from the policy" />;
  if (zones.error) return <ErrorPanel error={zones.error} onRetry={zones.reload} />;
  if (!zones.data) return null;

  return (
    <div className="space-y-4">
      <Card variant="default" className="p-5">
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label className="mb-1 block text-[11px] uppercase tracking-wider text-[#65738B]">
              Attacker's foothold (origin zone)
            </label>
            <select
              value={selected}
              onChange={(e) => setZone(e.target.value)}
              className="rounded-xl border border-[rgba(100,150,220,0.2)] bg-[rgba(5,11,24,0.8)] px-3 py-2 text-sm text-[#F5F8FF]"
            >
              {zones.data.source_zones.map((z) => (
                <option key={z} value={z}>
                  {z}
                  {zones.data?.untrusted.includes(z) ? '  (untrusted)' : ''}
                </option>
              ))}
            </select>
          </div>
          <button
            onClick={() => run(selected)}
            disabled={!selected || busy}
            className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-[#1677FF] to-[#2D8CFF] px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
          >
            <Crosshair className="h-4 w-4" />
            {busy ? 'Walking the policy…' : 'Compute blast radius'}
          </button>
        </div>
        <p className="mt-3 text-[12px] text-[#8FA0BC]">
          Probes every other zone on the ports attackers use to move laterally —
          remote administration first, then data stores — and names the rule that
          permits each path. Reachable is not exploitable: policy permitting a
          packet says nothing about whether a service is listening or patched.
        </p>
      </Card>

      {err instanceof ApiError && <ErrorPanel error={err} onRetry={() => run(selected)} />}
      {result && <BlastResult id={id} r={result} />}
    </div>
  );
};

const BlastResult: FC<{ id: string; r: BlastResponse }> = ({ id, r }) => {
  const s = r.summary;
  const byZone = useMemo(() => {
    const m = new Map<string, typeof r.reachable>();
    for (const step of r.reachable) {
      m.set(step.to_zone, [...(m.get(step.to_zone) ?? []), step]);
    }
    return m;
  }, [r]);
  const rules = useMemo(
    () => Array.from(new Set(r.reachable.map((p) => p.decided_by))).sort(),
    [r],
  );

  return (
    <div className="space-y-4">
      {s.latent && s.paths_open > 0 && (
        <div className="rounded-2xl border border-[rgba(245,184,46,0.3)] bg-[rgba(245,184,46,0.07)] p-4 text-[12.5px] leading-relaxed text-[#AAB8D0]">
          <strong className="text-[#F5B82E]">Latent exposure.</strong> Nothing is
          in {s.origin} today — no interface and no access point. The policy
          permits every path below, and they go live the moment something joins
          the zone, with no firewall change needed.
        </div>
      )}
      {s.origin_populated === true && (
        <div className="rounded-2xl border border-[rgba(229,72,77,0.3)] bg-[rgba(229,72,77,0.06)] p-4 text-[12.5px] text-[#AAB8D0]">
          <strong className="text-[#E5484D]">Live.</strong> {s.origin} contains{' '}
          {s.origin_members.slice(0, 4).join(', ')}.
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          ['Paths open', s.paths_open],
          ['Administrative', s.administrative_paths],
          [`Zones reached (of ${s.zones_considered})`, s.zones_reachable],
          ['Undecidable probes', s.undecidable],
        ].map(([label, value]) => (
          <Card key={label as string} variant="panel">
            <span className="block text-xl font-bold text-[#F5F8FF]">{String(value)}</span>
            <span className="text-[11px] text-[#8FA0BC]">{label}</span>
          </Card>
        ))}
      </div>

      {s.zones_fully_undecidable.length > 0 && (
        <p className="rounded-xl border border-[rgba(100,150,220,0.16)] p-3 text-[12px] text-[#AAB8D0]">
          <strong className="text-[#F5F8FF]">Unproven, not absent:</strong> every
          probe into {s.zones_fully_undecidable.join(', ')} was undecidable — no
          rule matched and this platform does not state its default policy.
        </p>
      )}

      {Array.from(byZone.entries()).map(([z, steps]) => (
        <Card key={z} variant="default" className="p-4">
          <h4 className="mb-2 text-sm font-bold text-[#F5F8FF]">
            {s.origin} → {z}{' '}
            <span className="text-[12px] font-normal text-[#8FA0BC]">
              {steps.length} path(s)
            </span>
          </h4>
          <div className="grid gap-1.5 sm:grid-cols-2">
            {steps.map((p) => (
              <div
                key={`${p.protocol}${p.port}`}
                className="flex items-center gap-2 rounded-lg bg-[rgba(5,11,24,0.8)] px-2 py-1 text-[12px]"
              >
                {p.administrative ? (
                  <Badge variant="critical">admin</Badge>
                ) : (
                  <Badge variant="default">data</Badge>
                )}
                <span className="font-mono text-[#DDE7F7]">
                  {p.protocol}/{p.port}
                </span>
                <span className="truncate text-[#8FA0BC]">{p.service}</span>
                {p.uncertain && <Badge variant="warning">uncertain</Badge>}
              </div>
            ))}
          </div>
          <p className="mt-2 font-mono text-[11px] text-[#65738B]">
            permitted by {Array.from(new Set(steps.map((p) => p.decided_by))).join(', ')}
          </p>
        </Card>
      ))}

      {rules.length > 0 && <SimulateClose id={id} zone={s.origin} rules={rules} />}
    </div>
  );
};

const SimulateClose: FC<{ id: string; zone: string; rules: string[] }> = ({
  id,
  zone,
  rules,
}) => {
  const [picked, setPicked] = useState<string[]>(rules);
  const [out, setOut] = useState<WhatIfResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);

  const toggle = (r: string) =>
    setPicked((p) => (p.includes(r) ? p.filter((x) => x !== r) : [...p, r]));

  const run = async () => {
    setBusy(true);
    setErr(null);
    try {
      setOut(await api.whatIf(id, { disable_rules: picked, origin_zone: zone }));
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  };

  const b = out?.blast_radius;
  return (
    <Card variant="default" className="p-5">
      <div className="flex items-center gap-2">
        <FlaskConical className="h-4 w-4 text-[#9B78FF]" />
        <h4 className="text-sm font-bold text-[#F5F8FF]">Simulate closing these rules</h4>
      </div>
      <p className="mt-1 text-[12px] text-[#8FA0BC]">
        Runs on a copy. Nothing on the device, and nothing in the stored
        assessment, changes.
      </p>
      <div className="mt-3 space-y-1.5">
        {rules.map((r) => (
          <label key={r} className="flex items-center gap-2 text-[12.5px] text-[#DDE7F7]">
            <input type="checkbox" checked={picked.includes(r)} onChange={() => toggle(r)} />
            <span className="font-mono">{r}</span>
          </label>
        ))}
      </div>
      <button
        onClick={run}
        disabled={busy || picked.length === 0}
        className="mt-3 rounded-xl border border-[rgba(155,120,255,0.4)] px-4 py-2 text-sm font-semibold text-[#9B78FF] disabled:opacity-50"
      >
        {busy ? 'Simulating…' : `Simulate disabling ${picked.length} rule(s)`}
      </button>

      {err instanceof ApiError && <ErrorPanel error={err} onRetry={run} />}

      {out && (
        <div className="mt-4 space-y-3">
          <p className="rounded-xl border border-[rgba(155,120,255,0.3)] bg-[rgba(155,120,255,0.06)] p-3 text-[12px] text-[#AAB8D0]">
            {out.label}
          </p>
          {out.warnings.map((w) => (
            <p
              key={w}
              className="rounded-xl border border-[rgba(229,72,77,0.3)] bg-[rgba(229,72,77,0.06)] p-3 text-[12.5px] text-[#DDE7F7]"
            >
              <strong className="text-[#E5484D]">Not closed: </strong>
              {w}
            </p>
          ))}
          {b && (
            <div className="grid grid-cols-2 gap-3">
              {(
                [
                  ['Paths open', b.before.paths_open, b.after.paths_open],
                  ['Administrative', b.before.administrative_paths, b.after.administrative_paths],
                ] as const
              ).map(([label, before, after]) => (
                <Card key={label} variant="panel">
                  <span className="block text-lg font-bold text-[#F5F8FF]">
                    {before} → {after}
                  </span>
                  <span className="text-[11px] text-[#8FA0BC]">{label}</span>
                </Card>
              ))}
            </div>
          )}
          <p className="text-[12px] text-[#AAB8D0]">
            Compliance score {out.before.score_pct ?? '—'}% →{' '}
            <strong className="text-[#F5F8FF]">{out.after.score_pct ?? '—'}%</strong>{' '}
            on {out.before.assessed_pct}% → {out.after.assessed_pct}% coverage.
          </p>
          <ul className="space-y-1 text-[11.5px] text-[#8FA0BC]">
            {out.caveats.map((c) => (
              <li key={c}>· {c}</li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
};
