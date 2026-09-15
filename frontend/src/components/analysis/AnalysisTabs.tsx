import { useState, type FC } from 'react';
import {
  Activity,
  Boxes,
  Camera,
  Crosshair,
  FlaskConical,
  GitCompare,
  ShieldAlert,
  Network,
  Route,
  ScrollText,
  Stamp,
} from 'lucide-react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Empty, ErrorPanel, Loading, NotRun } from '../ui/States';
import { api, ApiError, type ReachResponse } from '../../lib/api';
import { useApi } from '../../lib/useApi';
import { GraphPanel } from './GraphPanel';
import { BlastPanel } from './BlastPanel';
import { ExtendedPanel } from './ExtendedPanel';
import { WhatIfPanel } from './WhatIfPanel';

/**
 * The eight capabilities that were built, tested, and callable from nowhere.
 *
 * Each panel obeys the same contract as the engine behind it: when an analysis
 * could not run, it says so and says why. None of them renders an empty chart
 * or a zero, because on this product a zero means "we looked and found
 * nothing" -- and claiming that when we never looked would undo the engine's
 * central guarantee at the last layer.
 */

type Panel =
  | 'graph'
  | 'blast'
  | 'whatif'
  | 'extended'
  | 'hygiene'
  | 'reach'
  | 'recert'
  | 'change'
  | 'topology'
  | 'consensus'
  | 'training';

const PANELS: { id: Panel; label: string; icon: typeof Activity }[] = [
  // The graph leads, because everything after it is a conclusion drawn from it.
  { id: 'graph', label: 'Policy graph', icon: Boxes },
  // Blast radius and what-if are conclusions drawn from the graph, so they sit
  // straight after it. Extended checks are reported beside the score.
  { id: 'blast', label: 'Blast radius', icon: Crosshair },
  { id: 'whatif', label: 'What-if', icon: FlaskConical },
  { id: 'extended', label: 'VPN · Wireless · CVE', icon: ShieldAlert },
  { id: 'hygiene', label: 'Rule hygiene', icon: Activity },
  { id: 'reach', label: 'Reachability', icon: Route },
  { id: 'recert', label: 'Recertification', icon: Stamp },
  { id: 'change', label: 'Change tracking', icon: GitCompare },
  { id: 'topology', label: 'Interfaces', icon: Network },
  { id: 'consensus', label: 'Cross-check', icon: ScrollText },
  { id: 'training', label: 'Training queue', icon: Camera },
];

export const AnalysisTabs: FC<{ assessmentId: string }> = ({ assessmentId }) => {
  const [panel, setPanel] = useState<Panel>('hygiene');

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        {PANELS.map((p) => {
          const Icon = p.icon;
          return (
            <button
              key={p.id}
              onClick={() => setPanel(p.id)}
              className={`flex items-center gap-2 rounded-full border px-3.5 py-1.5 text-xs font-semibold transition-colors ${
                panel === p.id
                  ? 'border-[#1677FF] bg-[rgba(22,119,255,0.14)] text-[#F5F8FF]'
                  : 'border-[rgba(100,150,220,0.18)] text-[#8FA0BC] hover:text-[#F5F8FF]'
              }`}
            >
              <Icon className="h-3.5 w-3.5" />
              {p.label}
            </button>
          );
        })}
      </div>

      {panel === 'graph' && <GraphPanel id={assessmentId} />}
      {panel === 'hygiene' && <HygienePanel id={assessmentId} />}
      {panel === 'reach' && <ReachPanel id={assessmentId} />}
      {panel === 'recert' && <RecertPanel id={assessmentId} />}
      {panel === 'blast' && <BlastPanel id={assessmentId} />}
      {panel === 'whatif' && <WhatIfPanel id={assessmentId} />}
      {panel === 'extended' && <ExtendedPanel id={assessmentId} />}
      {panel === 'change' && <ChangePanel id={assessmentId} />}
      {panel === 'topology' && <InterfacesPanel id={assessmentId} />}
      {panel === 'consensus' && <ConsensusPanel id={assessmentId} />}
      {panel === 'training' && <TrainingPanel id={assessmentId} />}
    </div>
  );
};

// ------------------------------------------------------------- rule hygiene

const HygienePanel: FC<{ id: string }> = ({ id }) => {
  const { data, loading, error, reload } = useApi(() => api.hygiene(id), [id]);

  if (loading) return <Loading label="Analysing rule hygiene" />;
  if (error) return <ErrorPanel error={error} onRetry={reload} />;
  if (!data) return null;

  // The load-bearing branch. `analysis_ran: false` means no rule-graph builder
  // exists for this platform, so nothing was attempted -- which is a different
  // thing from a policy with no problems.
  if (!data.analysis_ran || !data.summary) {
    return (
      <NotRun
        what="Rule hygiene"
        reason={data.reason}
        supported={data.supported_platforms}
      />
    );
  }

  const s = data.summary;
  return (
    <div className="space-y-4">
      <Card variant="default" className="p-6">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            ['Rules examined', s.rules_examined],
            ['Fully resolved', s.rules_fully_resolved],
            ['Unevaluable', s.unevaluable],
            ['Findings', s.findings],
          ].map(([label, value]) => (
            <div
              key={label as string}
              className="rounded-xl border border-[rgba(100,150,220,0.14)] p-3"
            >
              <span className="block text-xl font-bold text-[#F5F8FF]">
                {(value as number).toLocaleString()}
              </span>
              <span className="text-[11px] text-[#8FA0BC]">{label}</span>
            </div>
          ))}
        </div>

        {/* Unevaluable rules are published beside the findings, not buried. A
            rule we could not resolve is not a clean rule, and a summary that
            hid them would report the policy as tidier than we can confirm. */}
        {s.unevaluable > 0 && (
          <p className="mt-4 rounded-xl border border-[rgba(245,184,46,0.25)] bg-[rgba(245,184,46,0.06)] p-3 text-[12.5px] text-[#AAB8D0]">
            <strong className="text-[#F5B82E]">
              {s.unevaluable} of {s.rules_examined} rules could not be fully
              resolved.
            </strong>{' '}
            Their references point at objects this export does not contain, so
            any conclusion about them is incomplete — they are counted here
            rather than treated as clean.
          </p>
        )}

        <div className="mt-4 flex flex-wrap gap-2">
          {Object.entries(s.by_kind).map(([kind, n]) => (
            <Badge key={kind} variant="outline">
              {kind.replace(/_/g, ' ')} · {n}
            </Badge>
          ))}
        </div>
      </Card>

      <Card variant="default" className="overflow-hidden p-0">
        <div className="border-b border-[rgba(100,150,220,0.12)] p-4">
          <h4 className="text-sm font-bold text-[#F5F8FF]">
            Findings ({data.findings.length} shown)
          </h4>
        </div>
        <div className="max-h-[520px] overflow-y-auto">
          {data.findings.map((f, i) => (
            <div
              key={i}
              className="border-b border-[rgba(100,150,220,0.08)] px-4 py-3 last:border-0"
            >
              <div className="flex flex-wrap items-center gap-2">
                <Badge
                  variant={
                    f.severity === 'high'
                      ? 'critical'
                      : f.severity === 'medium'
                        ? 'warning'
                        : 'default'
                  }
                >
                  {f.kind.replace(/_/g, ' ')}
                </Badge>
                <span className="font-mono text-[11.5px] text-[#F5F8FF]">
                  {f.rule}
                </span>
                {f.hit_count !== null && (
                  <span className="text-[11px] text-[#65738B]">
                    {f.hit_count.toLocaleString()} hits
                  </span>
                )}
              </div>
              <p className="mt-1 text-[12.5px] leading-relaxed text-[#AAB8D0]">
                {f.detail}
              </p>
            </div>
          ))}
        </div>
      </Card>

      {data.unevaluable && data.unevaluable.length > 0 && (
        <Card variant="default" className="p-5">
          <h4 className="mb-2 text-sm font-bold text-[#F5F8FF]">
            Unresolved references
          </h4>
          <div className="max-h-56 space-y-1 overflow-y-auto">
            {data.unevaluable.map((u, i) => (
              <p key={i} className="font-mono text-[11.5px] text-[#8FA0BC]">
                {u}
              </p>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
};

// ------------------------------------------------------------- reachability

const ReachPanel: FC<{ id: string }> = ({ id }) => {
  const [form, setForm] = useState({
    source: 'any',
    destination: 'any',
    port: '3389',
    protocol: 'tcp',
    source_zone: '',
    destination_zone: '',
  });
  const [result, setResult] = useState<ReachResponse | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);

  const ask = async () => {
    setBusy(true);
    setError(null);
    try {
      setResult(
        await api.reach(id, {
          source: form.source || undefined,
          destination: form.destination || undefined,
          port: form.port ? Number(form.port) : undefined,
          protocol: form.protocol || undefined,
          source_zone: form.source_zone || undefined,
          destination_zone: form.destination_zone || undefined,
        }),
      );
    } catch (e) {
      setResult(null);
      setError(e instanceof ApiError ? e : new ApiError(0, String(e)));
    } finally {
      setBusy(false);
    }
  };

  const a = result?.answer;
  const verdict =
    a == null
      ? null
      : a.permitted === null
        ? 'UNDECIDABLE'
        : a.permitted
          ? 'PERMITTED'
          : 'DENIED';

  return (
    <div className="space-y-4">
      <Card variant="default" className="p-6">
        <h4 className="mb-1 text-sm font-bold text-[#F5F8FF]">
          Would this traffic be permitted?
        </h4>
        <p className="mb-4 text-[12.5px] text-[#8FA0BC]">
          Evaluated in policy order, first match wins. The answer names the rule
          that decided it.
        </p>
        <div className="grid gap-3 sm:grid-cols-3">
          {(
            [
              ['source', 'Source', '10.10.0.5 or any'],
              ['destination', 'Destination', '8.8.8.8 or any'],
              ['port', 'Port', '443'],
              ['protocol', 'Protocol', 'tcp'],
              ['source_zone', 'Source zone (optional)', 'trusted'],
              ['destination_zone', 'Dest zone (optional)', 'wan'],
            ] as const
          ).map(([key, label, ph]) => (
            <label key={key} className="block">
              <span className="mb-1 block text-[10.5px] uppercase tracking-wider text-[#65738B]">
                {label}
              </span>
              <input
                value={form[key]}
                placeholder={ph}
                onChange={(e) => setForm({ ...form, [key]: e.target.value })}
                className="w-full rounded-lg border border-[rgba(100,150,220,0.16)] bg-[rgba(11,21,40,0.6)] px-3 py-2 font-mono text-[13px] text-[#F5F8FF] outline-none placeholder:text-[#4A566B] focus:border-[#1677FF]"
              />
            </label>
          ))}
        </div>
        <button
          onClick={ask}
          disabled={busy}
          className="ncsa-btn-primary mt-4 rounded-full px-5 py-2.5 text-xs font-semibold disabled:opacity-60"
        >
          {busy ? 'Evaluating...' : 'Ask the policy'}
        </button>
      </Card>

      {error && <ErrorPanel error={error} />}

      {a && verdict && (
        <Card variant="default" className="p-6">
          <div className="flex flex-wrap items-center gap-3">
            <span
              className={`rounded-full border px-3 py-1 text-sm font-bold ${
                verdict === 'PERMITTED'
                  ? 'border-[rgba(229,72,77,0.3)] bg-[rgba(229,72,77,0.12)] text-[#E5484D]'
                  : verdict === 'DENIED'
                    ? 'border-[rgba(50,214,168,0.3)] bg-[rgba(50,214,168,0.12)] text-[#32D6A8]'
                    : 'border-[rgba(140,160,190,0.25)] bg-[rgba(140,160,190,0.10)] text-[#AAB8D0]'
              }`}
            >
              {verdict}
            </span>
            <span className="font-mono text-[13px] text-[#F5F8FF]">
              {a.query}
            </span>
          </div>

          {a.decided_by && (
            <p className="mt-3 text-[13px] text-[#AAB8D0]">
              Decided by{' '}
              <strong className="font-mono text-[#F5F8FF]">
                {a.decided_by}
              </strong>{' '}
              ({a.action}) — {a.reason}
            </p>
          )}

          {/* Both caveats matter. An unevaluable rule above the match could
              have decided differently, and a zone-scoped rule answering an
              unzoned question rests on an assumption the caller never made. */}
          {a.rules_unevaluable > 0 && (
            <p className="mt-3 rounded-xl border border-[rgba(245,184,46,0.25)] bg-[rgba(245,184,46,0.06)] p-3 text-[12.5px] text-[#AAB8D0]">
              <strong className="text-[#F5B82E]">Caveat.</strong>{' '}
              {a.rules_unevaluable} rule
              {a.rules_unevaluable === 1 ? '' : 's'} above this one could not be
              evaluated. A match there would have decided differently.
            </p>
          )}
          {a.zone_assumed && (
            <p className="mt-2 rounded-xl border border-[rgba(45,140,255,0.25)] bg-[rgba(45,140,255,0.06)] p-3 text-[12.5px] text-[#AAB8D0]">
              <strong className="text-[#2D8CFF]">Zone assumed.</strong> The
              deciding rule is scoped to zones this query did not name, so it
              was assumed to apply. Fill in the zone fields to remove the
              assumption.
            </p>
          )}

          <pre className="mt-4 overflow-x-auto whitespace-pre-wrap rounded-xl border border-[rgba(100,150,220,0.16)] bg-[rgba(5,11,24,0.8)] p-4 text-[12px] text-[#DDE7F7]">
            {result.explain}
          </pre>
        </Card>
      )}
    </div>
  );
};

// ---------------------------------------------------------- recertification

const RecertPanel: FC<{ id: string }> = ({ id }) => {
  const { data, loading, error, reload } = useApi(
    () => api.recertification(id),
    [id],
  );

  if (loading) return <Loading label="Reviewing certifications" />;
  if (error) return <ErrorPanel error={error} onRetry={reload} />;
  if (!data) return null;

  return (
    <div className="space-y-4">
      <Card variant="default" className="overflow-hidden p-0">
        <div className="border-b border-[rgba(100,150,220,0.12)] p-4">
          <h4 className="text-sm font-bold text-[#F5F8FF]">
            Due for review — {data.due.length}
          </h4>
          <p className="mt-0.5 text-[12px] text-[#8FA0BC]">
            Rules with no recorded owner, or whose certification has expired.
          </p>
        </div>
        <div className="max-h-96 overflow-y-auto">
          {data.due.length === 0 ? (
            <Empty label="Nothing due." />
          ) : (
            data.due.slice(0, 200).map((d, i) => (
              <div
                key={i}
                className="border-b border-[rgba(100,150,220,0.08)] px-4 py-2.5 last:border-0"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <Badge
                    variant={d.severity === 'high' ? 'critical' : 'warning'}
                  >
                    {d.kind}
                  </Badge>
                  <span className="font-mono text-[11.5px] text-[#F5F8FF]">
                    {d.rule_id}
                  </span>
                  {d.owner && (
                    <span className="text-[11px] text-[#8FA0BC]">
                      owner: {d.owner}
                    </span>
                  )}
                </div>
                <p className="mt-1 text-[12.5px] text-[#AAB8D0]">{d.detail}</p>
              </div>
            ))
          )}
        </div>
      </Card>

      <Card variant="default" className="overflow-hidden p-0">
        <div className="border-b border-[rgba(100,150,220,0.12)] p-4">
          <h4 className="text-sm font-bold text-[#F5F8FF]">
            Deletion candidates — {data.deletion_candidates.length}
          </h4>
          {/* Three independent signals must agree before a rule is even a
              candidate, and it is still a candidate for review rather than an
              instruction. Any one signal alone is a bad reason to delete a
              firewall rule. */}
          <p className="mt-0.5 text-[12px] text-[#8FA0BC]">
            Ranked by how many independent signals agree. Candidates for review,
            never for automatic removal.
          </p>
        </div>
        <div className="max-h-96 overflow-y-auto">
          {data.deletion_candidates.slice(0, 200).map((c, i) => (
            <div
              key={i}
              className="border-b border-[rgba(100,150,220,0.08)] px-4 py-2.5 last:border-0"
            >
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="info">{c.confidence} signals</Badge>
                <span className="font-mono text-[11.5px] text-[#F5F8FF]">
                  {c.rule}
                </span>
              </div>
              <ul className="mt-1 list-inside list-disc text-[12px] text-[#AAB8D0]">
                {c.signals.map((s, j) => (
                  <li key={j}>{s}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
};

// ---------------------------------------------------------- change tracking

const ChangePanel: FC<{ id: string }> = ({ id }) => {
  const [busy, setBusy] = useState(false);
  const [snapMsg, setSnapMsg] = useState<string | null>(null);
  const { data, loading, error, reload } = useApi(() => api.diff(id), [id]);

  const takeSnapshot = async () => {
    setBusy(true);
    try {
      const s = await api.snapshot(id);
      setSnapMsg(`Snapshot recorded for ${s.device_key} at ${s.taken_at}`);
      reload();
    } catch (e) {
      setSnapMsg(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <Card variant="default" className="p-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h4 className="text-sm font-bold text-[#F5F8FF]">Baseline</h4>
            <p className="mt-0.5 text-[12.5px] text-[#8FA0BC]">
              Record this assessment so a later one can be compared against it.
            </p>
          </div>
          <button
            onClick={takeSnapshot}
            disabled={busy}
            className="ncsa-btn-primary rounded-full px-5 py-2.5 text-xs font-semibold disabled:opacity-60"
          >
            {busy ? 'Saving...' : 'Take snapshot'}
          </button>
        </div>
        {snapMsg && (
          <p className="mt-3 font-mono text-[12px] text-[#32D6A8]">{snapMsg}</p>
        )}
      </Card>

      {loading && <Loading label="Comparing against the last snapshot" />}
      {error && <ErrorPanel error={error} onRetry={reload} />}

      {data && data.note && <Empty label={data.note} />}

      {data && data.summary && (
        <Card variant="default" className="p-6">
          {/* Device change and analysis change are reported separately. A pack
              update altering a verdict is not configuration drift, and
              conflating them would have an operator chasing a change nobody
              made. */}
          <div className="flex flex-wrap gap-2">
            <Badge variant={data.summary.device_changed ? 'warning' : 'default'}>
              Configuration {data.summary.device_changed ? 'changed' : 'identical'}
            </Badge>
            <Badge
              variant={data.summary.analysis_changed ? 'info' : 'default'}
            >
              Analysis {data.summary.analysis_changed ? 'changed' : 'identical'}
            </Badge>
            <Badge variant={data.same_device ? 'success' : 'critical'}>
              {data.same_device ? 'Same device' : 'DIFFERENT DEVICE'}
            </Badge>
          </div>

          <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              ['Improved', data.summary.improved],
              ['Regressed', data.summary.regressed],
              ['Coverage changes', data.summary.coverage_changes],
              ['Rules changed',
                data.summary.rules.added +
                  data.summary.rules.removed +
                  data.summary.rules.modified],
            ].map(([label, value]) => (
              <div
                key={label as string}
                className="rounded-xl border border-[rgba(100,150,220,0.14)] p-3"
              >
                <span className="block text-xl font-bold text-[#F5F8FF]">
                  {value as number}
                </span>
                <span className="text-[11px] text-[#8FA0BC]">{label}</span>
              </div>
            ))}
          </div>

          {data.explain && (
            <pre className="mt-4 overflow-x-auto whitespace-pre-wrap rounded-xl border border-[rgba(100,150,220,0.16)] bg-[rgba(5,11,24,0.8)] p-4 text-[12px] text-[#DDE7F7]">
              {data.explain}
            </pre>
          )}
        </Card>
      )}
    </div>
  );
};

// --------------------------------------------------------------- interfaces

const InterfacesPanel: FC<{ id: string }> = ({ id }) => {
  const { data, loading, error, reload } = useApi(() => api.interfaces(id), [id]);

  if (loading) return <Loading label="Reading interfaces" />;
  if (error) return <ErrorPanel error={error} onRetry={reload} />;
  if (!data) return null;

  // A redacted upload has no addressing, so topology genuinely cannot be
  // inferred. The engine says why; repeating it here beats an empty table.
  if (data.note) return <NotRun what="Topology" reason={data.note} />;
  if (!data.interfaces.length)
    return <Empty label="No addressed interfaces were found." />;

  return (
    <Card variant="default" className="overflow-hidden p-0">
      <div className="border-b border-[rgba(100,150,220,0.12)] p-4">
        <h4 className="text-sm font-bold text-[#F5F8FF]">
          Interfaces — {data.interfaces.length}
        </h4>
        <p className="mt-0.5 text-[12px] text-[#8FA0BC]">
          The addressing that multi-device topology is inferred from. Adjacency
          is inferred from shared subnets, not read from the wire.
        </p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[rgba(100,150,220,0.12)] text-left text-[11px] uppercase tracking-wider text-[#65738B]">
              <th className="px-4 py-2.5 font-semibold">Interface</th>
              <th className="px-4 py-2.5 font-semibold">Address</th>
              <th className="px-4 py-2.5 font-semibold">Network</th>
              <th className="px-4 py-2.5 font-semibold">Zone</th>
              <th className="px-4 py-2.5 font-semibold">State</th>
            </tr>
          </thead>
          <tbody>
            {data.interfaces.map((i) => (
              <tr
                key={i.name}
                className="border-b border-[rgba(100,150,220,0.08)] last:border-0"
              >
                <td className="px-4 py-2.5 font-mono text-[#F5F8FF]">{i.name}</td>
                <td className="px-4 py-2.5 font-mono text-[#AAB8D0]">
                  {i.address ?? '—'}
                </td>
                <td className="px-4 py-2.5 font-mono text-[#AAB8D0]">
                  {i.network ?? '—'}
                </td>
                <td className="px-4 py-2.5 text-[#AAB8D0]">{i.zone ?? '—'}</td>
                <td className="px-4 py-2.5">
                  <Badge variant={i.enabled ? 'success' : 'default'}>
                    {i.enabled ? 'up' : 'down'}
                  </Badge>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
};

// ---------------------------------------------------------------- consensus

const ConsensusPanel: FC<{ id: string }> = ({ id }) => {
  const { data, loading, error, reload } = useApi(() => api.consensus(id), [id]);

  if (loading) return <Loading label="Cross-checking parsers" />;
  if (error) return <ErrorPanel error={error} onRetry={reload} />;
  if (!data) return null;

  const items = data.consensus?.items ?? [];

  return (
    <div className="space-y-4">
      <Card variant="default" className="p-6">
        <h4 className="mb-1 text-sm font-bold text-[#F5F8FF]">
          Independent cross-check
        </h4>
        <p className="mb-4 text-[12.5px] text-[#8FA0BC]">
          Two methods read the same device: the mapping pack reads the grammar,
          a detector reads the raw text. Agreement promotes a caveat to a
          conclusion; disagreement is surfaced, not silently resolved.
        </p>
        <div className="flex flex-wrap gap-2">
          <Badge variant="info">
            pack-only findings · {data.consensus?.pack_only ?? 0}
          </Badge>
          <Badge variant="outline">cross-checked · {items.length}</Badge>
        </div>
      </Card>

      {items.length === 0 ? (
        <Empty label="No cross-checked items for this device." />
      ) : (
        <Card variant="default" className="overflow-hidden p-0">
          {items.map((it, i) => (
            <div
              key={i}
              className="border-b border-[rgba(100,150,220,0.08)] p-4 last:border-0"
            >
              <div className="flex flex-wrap items-center gap-2">
                <Badge
                  variant={it.verdict === 'CONFIRMED' ? 'success' : 'warning'}
                >
                  {it.verdict}
                </Badge>
                <span className="font-mono text-[11.5px] text-[#F5F8FF]">
                  {it.field}
                </span>
                <span className="text-[11px] text-[#65738B]">
                  {it.detector}
                </span>
              </div>
              <div className="mt-2 grid gap-2 sm:grid-cols-2">
                <div className="rounded-lg border border-[rgba(100,150,220,0.14)] p-2.5">
                  <span className="text-[10.5px] uppercase tracking-wider text-[#65738B]">
                    Detector says
                  </span>
                  <p className="mt-0.5 text-[12.5px] text-[#AAB8D0]">
                    {it.universal_says}
                  </p>
                </div>
                <div className="rounded-lg border border-[rgba(100,150,220,0.14)] p-2.5">
                  <span className="text-[10.5px] uppercase tracking-wider text-[#65738B]">
                    Pack says
                  </span>
                  <p className="mt-0.5 font-mono text-[12.5px] text-[#AAB8D0]">
                    {it.pack_says}
                  </p>
                </div>
              </div>
              {it.note && (
                <p className="mt-2 text-[12px] italic text-[#8FA0BC]">
                  {it.note}
                </p>
              )}
            </div>
          ))}
        </Card>
      )}
    </div>
  );
};

// ----------------------------------------------------------- training queue

const TrainingPanel: FC<{ id: string }> = ({ id }) => {
  const { data, loading, error, reload } = useApi(() => api.training(id), [id]);

  if (loading) return <Loading label="Reading the training queue" />;
  if (error) return <ErrorPanel error={error} onRetry={reload} />;
  if (!data) return null;
  if (!data.length) return <Empty label="Nothing unrecognised on this device." />;

  return (
    <Card variant="default" className="overflow-hidden p-0">
      <div className="border-b border-[rgba(100,150,220,0.12)] p-4">
        <h4 className="text-sm font-bold text-[#F5F8FF]">
          Unrecognised settings — {data.length}
        </h4>
        <p className="mt-0.5 text-[12px] text-[#8FA0BC]">
          Settings the pack does not map yet, ordered by how likely the proposed
          field is. Approving one must pass the golden-corpus regression gate
          before it is accepted — and a high confidence is a reason to look
          first, never a reason to accept unread.
        </p>
      </div>
      <div className="max-h-[520px] overflow-y-auto">
        {data.slice(0, 200).map((c, i) => (
          <div
            key={i}
            className="border-b border-[rgba(100,150,220,0.08)] px-4 py-3 last:border-0"
          >
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-[12px] text-[#F5F8FF]">
                {c.name}
              </span>
              <span className="text-[11px] text-[#65738B]">
                {c.occurrences.toLocaleString()}×
              </span>
              <Badge variant="default">{c.status}</Badge>
            </div>
            {c.suggested_field && (
              <p className="mt-1 flex flex-wrap items-center gap-2 text-[12px] text-[#AAB8D0]">
                <span>
                  suggests{' '}
                  <span className="font-mono text-[#2D8CFF]">
                    {c.suggested_field}
                  </span>
                </span>
                {/* Banded, because the number is an ordering aid rather than a
                    probability. Measured precision on 378 held-out pairs:
                    80+ = 100%, 60-79 = 88%, 40-59 = 82%, below 40 = 56%.
                    Even the top band produces wrong proposals, so nothing here
                    is styled to suggest it can be accepted unread. */}
                <span
                  title={
                    'Ordering aid, not a probability. Measured precision on ' +
                    '378 held-out pairs: 80+ ≈ 100%, 60–79 ≈ 88%, 40–59 ≈ 82%, ' +
                    'below 40 ≈ 56%. Every proposal still needs review.'
                  }
                  className={`rounded-full border px-2 py-0.5 text-[10.5px] font-semibold ${
                    c.suggestion_score >= 60
                      ? 'border-[rgba(50,214,168,0.3)] bg-[rgba(50,214,168,0.12)] text-[#32D6A8]'
                      : c.suggestion_score >= 40
                        ? 'border-[rgba(245,184,46,0.3)] bg-[rgba(245,184,46,0.12)] text-[#F5B82E]'
                        : 'border-[rgba(140,160,190,0.22)] bg-[rgba(140,160,190,0.10)] text-[#AAB8D0]'
                  }`}
                >
                  {c.suggestion_score.toFixed(0)} confidence
                </span>
                <span className="text-[#65738B]">{c.suggested_from}</span>
              </p>
            )}
            <p className="mt-1 font-mono text-[11px] text-[#65738B]">
              {c.evidence.raw}
            </p>
          </div>
        ))}
      </div>
    </Card>
  );
};
