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
            <label className="mb-1 block text-[11px] uppercase tracking-wider text-[var(--color-slate-gray)]">
              Attacker's foothold (origin zone)
            </label>
            <select
              value={selected}
              onChange={(e) => setZone(e.target.value)}
              className="rounded-xl border border-[var(--color-hairline)] bg-[var(--color-pebble)] px-3 py-2 text-sm text-[var(--color-ink-navy)]"
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
            className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-[var(--color-signal-blue)] to-[var(--color-signal-blue)] px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
          >
            <Crosshair className="h-4 w-4" />
            {busy ? 'Walking the policy…' : 'Compute blast radius'}
          </button>
        </div>
        <p className="mt-3 text-xs text-[var(--color-slate-gray)]">
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
        <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4 text-xs leading-relaxed text-[var(--color-slate-gray)]">
          <strong className="text-[#b45309]">Latent exposure.</strong> Nothing is
          in {s.origin} today — no interface and no access point. The policy
          permits every path below, and they go live the moment something joins
          the zone, with no firewall change needed.
        </div>
      )}
      {s.origin_populated === true && (
        <div className="rounded-2xl border border-rose-200 bg-rose-50 p-4 text-xs text-[var(--color-slate-gray)]">
          <strong className="text-[#be123c]">Live.</strong> {s.origin} contains{' '}
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
            <span className="block text-xl font-bold text-[var(--color-ink-navy)]">{String(value)}</span>
            <span className="text-[11px] text-[var(--color-slate-gray)]">{label}</span>
          </Card>
        ))}
      </div>

      <AttackSurface r={r} />

      {s.zones_fully_undecidable.length > 0 && (
        <p className="rounded-xl border border-[var(--color-hairline)] p-3 text-xs text-[var(--color-slate-gray)]">
          <strong className="text-[var(--color-ink-navy)]">Unproven, not absent:</strong> every
          probe into {s.zones_fully_undecidable.join(', ')} was undecidable — no
          rule matched and this platform does not state its default policy.
        </p>
      )}

      {Array.from(byZone.entries()).map(([z, steps]) => (
        <Card key={z} variant="default" className="p-4">
          <h4 className="mb-2 text-sm font-bold text-[var(--color-ink-navy)]">
            {s.origin} → {z}{' '}
            <span className="text-xs font-normal text-[var(--color-slate-gray)]">
              {steps.length} path(s)
            </span>
          </h4>
          <div className="grid gap-1.5 sm:grid-cols-2">
            {steps.map((p) => (
              <div
                key={`${p.protocol}${p.port}`}
                className="flex items-center gap-2 rounded-lg bg-[var(--color-pebble)] px-2 py-1 text-xs"
              >
                {p.administrative ? (
                  <Badge variant="critical">admin</Badge>
                ) : (
                  <Badge variant="default">data</Badge>
                )}
                <span className="font-mono text-[var(--color-ink-navy)]">
                  {p.protocol}/{p.port}
                </span>
                <span className="truncate text-[var(--color-slate-gray)]">{p.service}</span>
                {p.uncertain && <Badge variant="warning">uncertain</Badge>}
              </div>
            ))}
          </div>
          <p className="mt-2 font-mono text-[11px] text-[var(--color-slate-gray)]">
            permitted by {Array.from(new Set(steps.map((p) => p.decided_by))).join(', ')}
          </p>
        </Card>
      ))}

      {rules.length > 0 && <SimulateClose id={id} zone={s.origin} rules={rules} />}
    </div>
  );
};

/**
 * What the open paths would let an attacker attempt.
 *
 * The engine reports ports; an administrator has to translate those into
 * consequences, and that translation is where a report usually loses people.
 * Ports are grouped by what reaching them enables, and each group says plainly
 * what an attacker with that foothold could try.
 *
 * The line held throughout: a permitted path is exposure, not proof. Policy
 * allowing a packet says nothing about whether a service is listening, patched
 * or authenticated -- so every heading describes what could be ATTEMPTED.
 */
const ATTACK_CLASSES: {
  match: (p: { port: number; administrative: boolean }) => boolean;
  title: string;
  attempt: string;
}[] = [
  {
    match: (p) => [445, 139].includes(p.port),
    title: 'Reach file shares and move sideways',
    attempt:
      'Enumerate shares, harvest credentials from them, and use the same ' +
      'credentials on the next host. This is the usual path from one ' +
      'compromised machine to a whole network.',
  },
  {
    match: (p) => [3389, 5900, 5901].includes(p.port),
    title: 'Open an interactive desktop session',
    attempt:
      'Attempt remote desktop or VNC login. These services are heavily ' +
      'targeted by credential-stuffing and are a common ransomware entry point.',
  },
  {
    match: (p) => [1433, 3306, 5432, 1521, 27017, 6379, 9200].includes(p.port),
    title: 'Reach databases directly',
    attempt:
      'Connect straight to the database engine, bypassing whatever the ' +
      'application enforces. If it accepts a weak or default login, the data ' +
      'can be read or copied wholesale.',
  },
  {
    match: (p) => [80, 443, 8080, 8443, 8000].includes(p.port),
    title: 'Reach web applications',
    attempt:
      'Probe the web application behind the port for its own flaws — ' +
      'injection, broken authentication, unpatched components.',
  },
  {
    match: (p) => [25, 110, 143, 465, 587, 993, 995].includes(p.port),
    title: 'Reach mail services',
    attempt: 'Attempt relay, mailbox access, or credential capture.',
  },
  {
    match: (p) => [53, 123, 161, 162].includes(p.port),
    title: 'Reach infrastructure services',
    attempt:
      'DNS, NTP and SNMP shape how everything else behaves. Reaching them ' +
      'invites poisoning, time manipulation, or device enumeration.',
  },
  // LAST on purpose. The engine marks anything reaching a management plane as
  // administrative, which includes SMB, RDP and RPC -- so testing this flag
  // first swept those into "take over administration" and buried what they
  // actually are. Specific ports win; this catches the rest.
  {
    match: (p) => p.administrative,
    title: 'Take over device administration',
    attempt:
      'Reach a management interface and try to log in — default, reused or ' +
      'brute-forced credentials, or a known authentication bypass. Success ' +
      'here means control of the device itself, not just traffic through it.',
  },
];

const AttackSurface: FC<{ r: BlastResponse }> = ({ r }) => {
  const groups = useMemo(() => {
    const out = new Map<
      string,
      { attempt: string; paths: typeof r.reachable }
    >();
    for (const p of r.reachable) {
      const cls =
        ATTACK_CLASSES.find((c) => c.match(p)) ?? {
          title: 'Reach other services',
          attempt:
            'The port is open from here. What it exposes depends on what is ' +
            'listening behind it.',
        };
      const cur = out.get(cls.title) ?? { attempt: cls.attempt, paths: [] };
      cur.paths.push(p);
      out.set(cls.title, cur);
    }
    return [...out.entries()].sort((a, b) => b[1].paths.length - a[1].paths.length);
  }, [r]);

  if (!groups.length) return null;

  return (
    <Card variant="default" className="p-5">
      <h4 className="text-sm font-bold text-[var(--color-ink-navy)]">
        What this exposure would let an attacker attempt
      </h4>
      <p className="mt-1 text-xs text-[var(--color-slate-gray)]">
        Grouped by consequence rather than by port number. Each group lists the
        zones it reaches and the rules that permit it. These are things an
        attacker could <em>try</em> from this foothold — the policy allows the
        packet through; whether a service answers, and whether it is patched, is
        not something a configuration file can tell us.
      </p>
      <div className="mt-4 space-y-3">
        {groups.map(([title, g]) => {
          const zones = Array.from(new Set(g.paths.map((p) => p.to_zone))).sort();
          const ports = Array.from(
            new Set(g.paths.map((p) => `${p.protocol}/${p.port}`)),
          ).sort();
          const rules = Array.from(new Set(g.paths.map((p) => p.decided_by))).sort();
          const uncertain = g.paths.filter((p) => p.uncertain).length;
          return (
            <div
              key={title}
              className="rounded-xl border border-[var(--color-hairline)] p-3"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-bold text-[var(--color-ink-navy)]">
                  {title}
                </span>
                <Badge variant={title.startsWith('Take over') ? 'critical' : 'default'}>
                  {g.paths.length} path{g.paths.length === 1 ? '' : 's'}
                </Badge>
                {uncertain > 0 && (
                  <Badge variant="warning">{uncertain} uncertain</Badge>
                )}
              </div>
              <p className="mt-1 text-xs leading-relaxed text-[var(--color-slate-gray)]">
                {g.attempt}
              </p>
              <p className="mt-2 text-[11px] text-[var(--color-slate-gray)]">
                <span className="font-semibold text-[var(--color-ink-navy)]">Reaches:</span>{' '}
                {zones.join(', ')}
                {'  ·  '}
                <span className="font-semibold text-[var(--color-ink-navy)]">On:</span>{' '}
                <span className="font-mono">{ports.join(', ')}</span>
              </p>
              <p className="mt-1 font-mono text-[11px] text-[var(--color-mist-gray)]">
                permitted by {rules.join(', ')}
              </p>
              {(() => {
                // One chip per technique, de-duplicated across the group's
                // paths. Named by the engine from the ATT&CK bundle, so a
                // technique shown here is one MITRE actually publishes.
                const techniques = new Map<string, string>();
                g.paths.forEach((p) =>
                  (p.attack ?? []).forEach((a) => techniques.set(a.id, a.name)),
                );
                if (!techniques.size) return null;
                return (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {[...techniques.entries()].sort().map(([tid, name]) => (
                      <span
                        key={tid}
                        className="rounded-full border border-rose-200 bg-rose-50 px-2 py-0.5 text-[10px] font-semibold text-[#be123c]"
                      >
                        ATT&amp;CK {tid} · {name}
                      </span>
                    ))}
                  </div>
                );
              })()}
            </div>
          );
        })}
      </div>
    </Card>
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
        <FlaskConical className="h-4 w-4 text-[#7c3aed]" />
        <h4 className="text-sm font-bold text-[var(--color-ink-navy)]">Simulate closing these rules</h4>
      </div>
      <p className="mt-1 text-xs text-[var(--color-slate-gray)]">
        Runs on a copy. Nothing on the device, and nothing in the stored
        assessment, changes.
      </p>
      <div className="mt-3 space-y-1.5">
        {rules.map((r) => (
          <label key={r} className="flex items-center gap-2 text-xs text-[var(--color-ink-navy)]">
            <input type="checkbox" checked={picked.includes(r)} onChange={() => toggle(r)} />
            <span className="font-mono">{r}</span>
          </label>
        ))}
      </div>
      <button
        onClick={run}
        disabled={busy || picked.length === 0}
        className="mt-3 rounded-xl border border-purple-200 px-4 py-2 text-sm font-semibold text-[#7c3aed] disabled:opacity-50"
      >
        {busy ? 'Simulating…' : `Simulate disabling ${picked.length} rule(s)`}
      </button>

      {err instanceof ApiError && <ErrorPanel error={err} onRetry={run} />}

      {out && (
        <div className="mt-4 space-y-3">
          <p className="rounded-xl border border-purple-200 bg-purple-50 p-3 text-xs text-[var(--color-slate-gray)]">
            {out.label}
          </p>
          {out.warnings.map((w) => (
            <p
              key={w}
              className="rounded-xl border border-rose-200 bg-rose-50 p-3 text-xs text-[var(--color-ink-navy)]"
            >
              <strong className="text-[#be123c]">Not closed: </strong>
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
                  <span className="block text-lg font-bold text-[var(--color-ink-navy)]">
                    {before} → {after}
                  </span>
                  <span className="text-[11px] text-[var(--color-slate-gray)]">{label}</span>
                </Card>
              ))}
            </div>
          )}
          <p className="text-xs text-[var(--color-slate-gray)]">
            Compliance score {out.before.score_pct ?? '—'}% →{' '}
            <strong className="text-[var(--color-ink-navy)]">{out.after.score_pct ?? '—'}%</strong>{' '}
            on {out.before.assessed_pct}% → {out.after.assessed_pct}% coverage.
          </p>
          <ul className="space-y-1 text-[11px] text-[var(--color-slate-gray)]">
            {out.caveats.map((c) => (
              <li key={c}>· {c}</li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
};
