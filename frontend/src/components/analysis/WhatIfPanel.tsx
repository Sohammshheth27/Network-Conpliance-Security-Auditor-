import { useMemo, useState, type FC } from 'react';
import { FlaskConical } from 'lucide-react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Empty, ErrorPanel, Loading } from '../ui/States';
import { api, ApiError, type WhatIfResponse } from '../../lib/api';
import { useApi } from '../../lib/useApi';

/**
 * What-if remediation: pick failures, see the score they would produce.
 *
 * Only FAIL and PARTIAL controls are offered. Offering UNKNOWN would let a
 * click turn "we could not read this" into a pass. Policy-derived findings
 * come back refused, with the rules to disable instead -- shown verbatim,
 * because the refusal is the useful part.
 */
export const WhatIfPanel: FC<{ id: string }> = ({ id }) => {
  const a = useApi(() => api.assessment(id), [id]);
  const [picked, setPicked] = useState<string[]>([]);
  const [out, setOut] = useState<WhatIfResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);

  const failing = useMemo(
    () =>
      (a.data?.findings ?? []).filter(
        (f) => f.state === 'FAIL' || f.state === 'PARTIAL',
      ),
    [a.data],
  );

  if (a.loading) return <Loading label="Loading findings" />;
  if (a.error) return <ErrorPanel error={a.error} onRetry={a.reload} />;
  if (!a.data) return null;
  if (failing.length === 0) return <Empty label="No failing controls to simulate." />;

  const toggle = (cid: string) =>
    setPicked((p) => (p.includes(cid) ? p.filter((x) => x !== cid) : [...p, cid]));

  const run = async () => {
    setBusy(true);
    setErr(null);
    try {
      setOut(await api.whatIf(id, { fix_controls: picked }));
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <Card variant="default" className="p-5">
        <div className="flex items-center gap-2">
          <FlaskConical className="h-4 w-4 text-[#9B78FF]" />
          <h3 className="text-sm font-bold text-[#F5F8FF]">What-if remediation</h3>
        </div>
        <p className="mt-1 text-[12px] text-[#8FA0BC]">
          Choose failures to fix. The engine re-scores a copy of this assessment
          with those settings corrected. Nothing on the device changes.
        </p>
        <div className="mt-3 max-h-72 space-y-1.5 overflow-y-auto pr-2">
          {failing.map((f) => (
            <label
              key={f.control_id}
              className="flex items-start gap-2 text-[12.5px] text-[#DDE7F7]"
            >
              <input
                type="checkbox"
                className="mt-0.5"
                checked={picked.includes(f.control_id)}
                onChange={() => toggle(f.control_id)}
              />
              <span className="font-mono text-[11px] text-[#8FA0BC]">{f.control_id}</span>
              <span>{f.title}</span>
              <span className="ml-auto text-[10.5px] uppercase text-[#65738B]">
                {f.severity}
              </span>
            </label>
          ))}
        </div>
        <button
          onClick={run}
          disabled={busy || picked.length === 0}
          className="mt-3 rounded-xl bg-gradient-to-r from-[#7B5CFF] to-[#9B78FF] px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
        >
          {busy ? 'Re-scoring…' : `Simulate fixing ${picked.length} control(s)`}
        </button>
      </Card>

      {err instanceof ApiError && <ErrorPanel error={err} onRetry={run} />}

      {out && (
        <Card variant="default" className="space-y-3 p-5">
          <p className="rounded-xl border border-[rgba(155,120,255,0.3)] bg-[rgba(155,120,255,0.06)] p-3 text-[12px] text-[#AAB8D0]">
            {out.label}
          </p>
          <div className="grid grid-cols-2 gap-3">
            <Card variant="panel">
              <span className="block text-2xl font-bold text-[#F5F8FF]">
                {out.before.score_pct ?? '—'}% → {out.after.score_pct ?? '—'}%
              </span>
              <span className="text-[11px] text-[#8FA0BC]">
                compliance score
                {out.delta.score_pct !== null && ` (${out.delta.score_pct >= 0 ? '+' : ''}${out.delta.score_pct})`}
              </span>
            </Card>
            <Card variant="panel">
              <span className="block text-2xl font-bold text-[#F5F8FF]">
                {out.before.assessed_pct}% → {out.after.assessed_pct}%
              </span>
              <span className="text-[11px] text-[#8FA0BC]">coverage</span>
            </Card>
          </div>

          {out.changes.length > 0 && (
            <div className="space-y-1">
              {out.changes.map((c) => (
                <div key={c.control_id} className="flex items-center gap-2 text-[12.5px]">
                  <span className="font-mono text-[11px] text-[#8FA0BC]">{c.control_id}</span>
                  <Badge variant="critical">{c.before}</Badge>
                  <span className="text-[#65738B]">→</span>
                  <Badge variant={c.after === 'PASS' ? 'success' : 'warning'}>{c.after}</Badge>
                  <span className="text-[#AAB8D0]">{c.title}</span>
                  {!c.targeted && <Badge variant="info">side effect</Badge>}
                </div>
              ))}
            </div>
          )}

          {out.rejected.map((r) => (
            <div
              key={r.item}
              className="rounded-xl border border-[rgba(245,184,46,0.3)] bg-[rgba(245,184,46,0.06)] p-3 text-[12.5px] text-[#AAB8D0]"
            >
              <strong className="text-[#F5B82E]">{r.item} not simulated: </strong>
              {r.reason}
              {r.suggest_disable_rules && r.suggest_disable_rules.length > 0 && (
                <span className="mt-1 block font-mono text-[11px] text-[#DDE7F7]">
                  rules behind it: {r.suggest_disable_rules.join(', ')} — use Blast
                  radius → Simulate closing
                </span>
              )}
            </div>
          ))}

          <ul className="space-y-1 text-[11.5px] text-[#8FA0BC]">
            {out.caveats.map((c) => (
              <li key={c}>· {c}</li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
};
