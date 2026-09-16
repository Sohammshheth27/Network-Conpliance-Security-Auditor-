import { useMemo, useState, type FC } from 'react';
import { useNavigate } from 'react-router-dom';
import { Check, RefreshCw, X } from 'lucide-react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Empty, ErrorPanel, Loading } from '../ui/States';
import {
  api,
  ApiError,
  type Assessment,
  type SchemaField,
  type TrainingCandidate,
} from '../../lib/api';
import { useApi } from '../../lib/useApi';

/**
 * The interactive training interface -- deliverable 2.
 *
 * An administrator sees each unrecognised setting as it appears in the file,
 * the AI's proposed meaning with its confidence, and chooses what it means.
 * Approving writes a learned mapping, which the golden-corpus regression gate
 * must accept; the gate's verdict is shown word for word, because a refusal
 * with a reason is the most useful thing this screen can say.
 *
 * For a vendor with no pack at all, the first approval creates its pack. The
 * form asks for the vendor, a platform id, the file format and a SIGNATURE --
 * without a signature the next upload of that vendor would be refused again.
 *
 * "Re-assess" runs the same file through the engine with everything learned.
 * Nothing is redeployed: that is the point being demonstrated.
 */

const APPROVER_KEY = 'ncsa.approver';

function readApprover(): string {
  try {
    return localStorage.getItem(APPROVER_KEY) ?? '';
  } catch {
    return '';
  }
}

type Verdict = { ok: boolean; text: string; detail?: string[]; alert?: boolean };

export const TrainingWorkbench: FC<{
  id: string;
  onReassessed?: (newId: string) => void;
}> = ({ id, onReassessed }) => {
  const ctx = useApi(() => api.trainingContext(id), [id]);
  const queue = useApi(() => api.training(id), [id]);
  const fields = useApi(() => api.schemaFields(), []);
  const navigate = useNavigate();

  const [approver, setApprover] = useState(readApprover);
  const [vendorIn, setVendor] = useState<string | null>(null);
  const [platformIn, setPlatform] = useState<string | null>(null);
  const [readerIn, setReader] = useState<string | null>(null);
  const [sigIn, setSig] = useState<string | null>(null);
  const [choice, setChoice] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [verdicts, setVerdicts] = useState<Record<string, Verdict>>({});
  const [learnedNow, setLearnedNow] = useState(0);
  const [after, setAfter] = useState<Assessment | null>(null);
  const [reBusy, setReBusy] = useState(false);
  const [reErr, setReErr] = useState<string | null>(null);

  const fieldMap = useMemo(
    () => new Map<string, SchemaField>((fields.data ?? []).map((f) => [f.field, f])),
    [fields.data],
  );

  if (ctx.loading || queue.loading) return <Loading label="Reading the training queue" />;
  if (ctx.error) return <ErrorPanel error={ctx.error} onRetry={ctx.reload} />;
  if (queue.error) return <ErrorPanel error={queue.error} onRetry={queue.reload} />;
  if (!ctx.data || !queue.data) return null;

  const c = ctx.data;
  const newVendor = !c.has_pack;
  // Form values are derived: what the user typed, else what the engine
  // suggested. No effect copies one into the other.
  const vendor = vendorIn ?? (c.vendor && c.vendor !== 'UNKNOWN' ? c.vendor : '');
  const platform = c.platform_known ? c.platform : (platformIn ?? '');
  const reader = readerIn ?? c.reader;
  const signature = sigIn ?? c.suggested_signature.join('\n');
  const sigs = signature.split('\n').map((s) => s.trim()).filter(Boolean);
  const vendorReady = !newVendor || (vendor.trim() && platform.trim() && sigs.length > 0);

  const approve = async (cand: TrainingCandidate) => {
    const field = choice[cand.name] ?? cand.suggested_field ?? '';
    if (!field || !approver.trim() || !vendorReady) return;
    setBusy(cand.name);
    try {
      try {
        localStorage.setItem(APPROVER_KEY, approver.trim());
      } catch {
        /* storage may be blocked; the approval does not depend on it */
      }
      const r = await api.approveMapping({
        setting_name: cand.name,
        field,
        platform: platform || c.platform,
        approved_by: approver.trim(),
        kind: cand.kind,
        assessment_id: id,
        ...(newVendor ? { vendor: vendor.trim(), reader, signature: sigs } : {}),
      });
      setVerdicts((v) => ({
        ...v,
        [cand.name]: {
          ok: r.accepted,
          text: r.reason,
          detail: r.regression?.detail,
          alert: r.regression?.direction_alert,
        },
      }));
      if (r.accepted) {
        setLearnedNow((n) => n + 1);
        ctx.reload();
      }
    } catch (e) {
      setVerdicts((v) => ({
        ...v,
        [cand.name]: { ok: false, text: e instanceof ApiError ? e.message : String(e) },
      }));
    } finally {
      setBusy(null);
    }
  };

  const reject = async (cand: TrainingCandidate) => {
    if (!approver.trim()) return;
    setBusy(cand.name);
    try {
      await api.rejectMapping({
        setting_name: cand.name,
        platform: platform || c.platform,
        rejected_by: approver.trim(),
      });
      queue.reload();
    } finally {
      setBusy(null);
    }
  };

  const runReassess = async () => {
    setReBusy(true);
    setReErr(null);
    try {
      const a = await api.reassess(id);
      setAfter(a);
      onReassessed?.(a.assessment_id);
    } catch (e) {
      setReErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setReBusy(false);
    }
  };

  const inputStyle = "mt-1 w-full rounded-lg border border-[var(--color-hairline)] bg-white px-2 py-1.5 text-sm text-[var(--color-ink-navy)] focus:outline-none focus:border-[var(--color-signal-blue)] focus:ring-1 focus:ring-[var(--color-signal-blue)] shadow-sm";

  return (
    <div className="space-y-6">
      <Card variant="default" className="space-y-4 p-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-base font-bold text-[var(--color-ink-navy)]">{c.source_file}</h3>
            <p className="text-xs text-[var(--color-slate-gray)] mt-0.5">
              {newVendor
                ? 'No pack exists for this device yet. The first approval creates it.'
                : `Known platform (${c.platform}). Approvals extend its pack.`}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant={c.supported ? 'success' : 'warning'}>
              {c.supported ? 'assessed' : 'not yet assessable'}
            </Badge>
            {learnedNow > 0 && <Badge variant="info">{learnedNow} learned this session</Badge>}
          </div>
        </div>

        <div className="pt-2">
          <label className="block text-xs font-semibold text-[var(--color-slate-gray)] uppercase tracking-wider mb-1">
            Approving as
            <input
              value={approver}
              onChange={(e) => setApprover(e.target.value)}
              placeholder="Your name -- every decision is attributed"
              className={`max-w-sm ${inputStyle} font-normal normal-case tracking-normal`}
            />
          </label>
        </div>

        {newVendor && (
          <div className="grid gap-4 rounded-xl border border-[rgba(245,184,46,0.3)] bg-[rgba(245,184,46,0.05)] p-5 sm:grid-cols-2 mt-4">
            <p className="text-xs text-[var(--color-slate-gray)] sm:col-span-2 leading-relaxed">
              <strong className="text-amber-700">Teaching a new vendor.</strong> The
              signature is how its next file will be recognised. It must match this
              file and no other vendor's sample, and the engine checks both before
              anything is written.
            </p>
            <label className="text-xs font-medium text-[var(--color-slate-gray)]">
              Vendor name
              <input
                value={vendor}
                onChange={(e) => setVendor(e.target.value)}
                placeholder="e.g. SONiC"
                className={inputStyle}
              />
            </label>
            <label className="text-xs font-medium text-[var(--color-slate-gray)]">
              Platform id {c.platform_known && '(recognised -- fixed)'}
              <input
                value={platform}
                disabled={c.platform_known}
                onChange={(e) => setPlatform(e.target.value)}
                placeholder="lower_case_id, e.g. acme_os"
                className={`${inputStyle} font-mono disabled:opacity-60 disabled:bg-[var(--color-pebble)]`}
              />
            </label>
            <label className="text-xs font-medium text-[var(--color-slate-gray)]">
              File format
              <select
                value={reader}
                onChange={(e) => setReader(e.target.value)}
                className={inputStyle}
              >
                {['json', 'xml', 'braces', 'indented', 'block'].map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </label>
            <label className="text-xs font-medium text-[var(--color-slate-gray)]">
              Signature ({reader === 'json' ? 'JSONPath' : 'regex'}, one per line)
              <textarea
                value={signature}
                onChange={(e) => setSig(e.target.value)}
                rows={2}
                className={`${inputStyle} font-mono text-xs`}
              />
            </label>
          </div>
        )}
      </Card>

      <datalist id="ncsa-fields">
        {(fields.data ?? []).map((f) => (
          <option key={f.field} value={f.field}>
            {f.type} · {f.controls.length} control(s)
          </option>
        ))}
      </datalist>

      {queue.data.length === 0 ? (
        <Empty label="Nothing unrecognised is waiting on this device." />
      ) : (
        <Card variant="default" className="overflow-hidden p-0">
          <div className="border-b border-[var(--color-hairline)] bg-[var(--color-cloud)] p-5">
            <h4 className="text-base font-bold text-[var(--color-ink-navy)]">
              Unrecognised settings — {queue.data.length}
            </h4>
            <p className="mt-1 text-xs text-[var(--color-slate-gray)] leading-relaxed max-w-4xl">
              A high confidence is a reason to look first, never a reason to accept
              unread: measured precision is about 100% above 80, 88% at 60–79, 82% at
              40–59 and 56% below 40.
            </p>
          </div>
          <div className="max-h-[640px] overflow-y-auto">
            {queue.data.slice(0, 200).map((cand) => {
              const picked = choice[cand.name] ?? cand.suggested_field ?? '';
              const meta = fieldMap.get(picked);
              const verdict = verdicts[cand.name];
              const keysMismatch = cand.kind === 'keys' && meta && meta.type !== 'list';
              return (
                <div
                  key={cand.name}
                  className="space-y-3 border-b border-[var(--color-hairline)] px-5 py-4 last:border-0 hover:bg-[var(--color-pebble)] transition-colors"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-sm font-semibold text-[var(--color-ink-navy)]">{cand.name}</span>
                    {cand.kind === 'keys' && <Badge variant="info">table keys</Badge>}
                    <span className="text-xs font-medium text-[var(--color-slate-gray)]">
                      {cand.occurrences.toLocaleString()}×
                    </span>
                    {cand.status === 'APPROVED' && <Badge variant="success">approved</Badge>}
                    {cand.sample_values.length > 0 && (
                      <span className="font-mono text-xs text-[var(--color-slate-gray)] ml-2">
                        e.g. {cand.sample_values.slice(0, 3).join(', ')}
                      </span>
                    )}
                  </div>
                  
                  {cand.evidence?.raw && (
                    <code className="block break-all rounded-lg bg-[var(--color-cloud)] border border-[var(--color-hairline)] px-3 py-2 font-mono text-xs text-[var(--color-ink-navy)] shadow-sm">
                      {cand.evidence.raw}
                    </code>
                  )}
                  
                  {cand.suggested_field && (
                    <p className="text-xs font-medium text-[var(--color-slate-gray)]">
                      AI suggests <span className="font-mono text-[var(--color-signal-blue)] font-bold">{cand.suggested_field}</span>{' '}
                      <span>
                        ({cand.suggestion_score.toFixed(0)} confidence, {cand.suggested_from})
                      </span>
                    </p>
                  )}
                  
                  <div className="flex flex-wrap items-center gap-3 pt-1">
                    <input
                      list="ncsa-fields"
                      value={picked}
                      onChange={(e) => setChoice((m) => ({ ...m, [cand.name]: e.target.value }))}
                      placeholder="choose the field this setting means"
                      className="min-w-[18rem] flex-1 rounded-lg border border-[var(--color-hairline)] bg-white px-3 py-2 font-mono text-xs text-[var(--color-ink-navy)] focus:outline-none focus:border-[var(--color-signal-blue)] focus:ring-1 focus:ring-[var(--color-signal-blue)] shadow-sm"
                    />
                    <button
                      onClick={() => approve(cand)}
                      disabled={busy !== null || !picked || !meta || !approver.trim() || !vendorReady}
                      className="flex items-center gap-1.5 rounded-lg bg-[var(--color-signal-blue)] px-4 py-2 text-xs font-bold text-white shadow-sm hover:opacity-90 disabled:opacity-40 disabled:hover:opacity-40 transition-opacity"
                    >
                      <Check className="h-4 w-4" />
                      {busy === cand.name ? 'Checking corpus…' : 'Approve'}
                    </button>
                    <button
                      onClick={() => reject(cand)}
                      disabled={busy !== null || !approver.trim()}
                      className="flex items-center gap-1.5 rounded-lg border border-[var(--color-hairline)] bg-white px-4 py-2 text-xs font-bold text-[var(--color-slate-gray)] hover:text-rose-600 hover:border-rose-200 hover:bg-rose-50 shadow-sm disabled:opacity-40 transition-colors"
                    >
                      <X className="h-4 w-4" />
                      Reject
                    </button>
                  </div>
                  
                  {picked && !meta && (
                    <p className="text-xs font-semibold text-amber-600">
                      Not a schema field. Pick one from the list.
                    </p>
                  )}
                  {meta && (
                    <p className="text-xs font-medium text-[var(--color-slate-gray)]">
                      {meta.type} field ·{' '}
                      {meta.controls.length
                        ? `read by ${meta.controls.join(', ')}`
                        : 'no control reads it yet (identity or inventory)'}
                    </p>
                  )}
                  {keysMismatch && (
                    <p className="text-xs font-semibold text-amber-600">
                      This setting is a table; its keys will be read as a list. Choose a
                      list-typed field.
                    </p>
                  )}
                  
                  {verdict && (
                    <div
                      className={`rounded-xl border p-3 text-xs ${
                        verdict.ok
                          ? 'border-[rgba(50,214,168,0.4)] bg-[rgba(50,214,168,0.05)] text-emerald-800'
                          : 'border-[rgba(245,184,46,0.4)] bg-[rgba(245,184,46,0.05)] text-amber-800'
                      }`}
                    >
                      <strong>{verdict.ok ? 'Learned. ' : 'Not learned. '}</strong>
                      {verdict.text}
                      {verdict.ok && ' Re-assess to apply it.'}
                      {verdict.alert && (
                        <span className="block mt-1 font-medium">
                          The corpus pass rate rose. That is what a poisoned mapping looks
                          like too -- worth a second look.
                        </span>
                      )}
                      {verdict.detail && verdict.detail.length > 0 && (
                        <div className="mt-2 space-y-1">
                          {verdict.detail.map((d) => (
                            <span key={d} className="block font-mono text-[11px] opacity-80">
                              {d}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </Card>
      )}

      <Card variant="default" className="flex flex-wrap items-center justify-between gap-4 p-6">
        <p className="max-w-2xl text-xs text-[var(--color-slate-gray)] leading-relaxed">
          Re-assess runs this same file again with everything learned so far. No
          restart and no redeploy: the next assessment simply reads the learned
          mappings.
        </p>
        <button
          onClick={runReassess}
          disabled={reBusy}
          className="flex items-center gap-2 rounded-xl border border-[rgba(0,107,255,0.3)] bg-[rgba(0,107,255,0.05)] px-5 py-2.5 text-sm font-bold text-[var(--color-signal-blue)] hover:bg-[rgba(0,107,255,0.1)] transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`h-4 w-4 ${reBusy ? 'animate-spin' : ''}`} />
          {reBusy ? 'Re-assessing…' : 'Re-assess with what was learned'}
        </button>
        
        {reErr && <p className="w-full text-sm font-semibold text-rose-600 mt-2">{reErr}</p>}
        
        {after && (
          <div className="w-full rounded-xl border border-[rgba(50,214,168,0.4)] bg-[rgba(50,214,168,0.05)] p-4 text-xs text-emerald-800 mt-4">
            <strong>{after.supported ? 'Now assessable. ' : 'Still not assessable. '}</strong>
            Coverage {c.coverage ? `${c.coverage.assessed_pct}%` : 'none'} →{' '}
            <span className="font-bold">{after.coverage.assessed_pct}%</span> · score{' '}
            {after.coverage.score_pct === null ? '—' : <span className="font-bold">{after.coverage.score_pct}%</span>} ·{' '}
            {after.coverage.controls_decided} controls decided.
            <button
              onClick={() => navigate(`/assessments/${after.assessment_id}`)}
              className="ml-3 font-bold text-[var(--color-signal-blue)] hover:underline inline-flex items-center gap-1"
            >
              Open the re-assessed device <span className="text-lg leading-none">→</span>
            </button>
          </div>
        )}
      </Card>
    </div>
  );
};
