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

  return (
    <div className="space-y-4">
      <Card variant="default" className="space-y-3 p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-[#F5F8FF]">{c.source_file}</h3>
            <p className="text-[12px] text-[#8FA0BC]">
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

        <label className="block text-[12px] text-[#AAB8D0]">
          Approving as
          <input
            value={approver}
            onChange={(e) => setApprover(e.target.value)}
            placeholder="your name -- every decision is attributed"
            className="mt-1 w-full max-w-sm rounded-xl border border-[rgba(100,150,220,0.2)] bg-[rgba(5,11,24,0.8)] px-3 py-2 text-sm text-[#F5F8FF]"
          />
        </label>

        {newVendor && (
          <div className="grid gap-3 rounded-xl border border-[rgba(245,184,46,0.25)] bg-[rgba(245,184,46,0.05)] p-4 sm:grid-cols-2">
            <p className="text-[12px] text-[#AAB8D0] sm:col-span-2">
              <strong className="text-[#F5B82E]">Teaching a new vendor.</strong> The
              signature is how its next file will be recognised. It must match this
              file and no other vendor's sample, and the engine checks both before
              anything is written.
            </p>
            <label className="text-[12px] text-[#AAB8D0]">
              Vendor name
              <input
                value={vendor}
                onChange={(e) => setVendor(e.target.value)}
                placeholder="e.g. SONiC"
                className="mt-1 w-full rounded-lg border border-[rgba(100,150,220,0.2)] bg-[rgba(5,11,24,0.8)] px-2 py-1.5 text-sm text-[#F5F8FF]"
              />
            </label>
            <label className="text-[12px] text-[#AAB8D0]">
              Platform id {c.platform_known && '(recognised -- fixed)'}
              <input
                value={platform}
                disabled={c.platform_known}
                onChange={(e) => setPlatform(e.target.value)}
                placeholder="lower_case_id, e.g. acme_os"
                className="mt-1 w-full rounded-lg border border-[rgba(100,150,220,0.2)] bg-[rgba(5,11,24,0.8)] px-2 py-1.5 font-mono text-sm text-[#F5F8FF] disabled:opacity-60"
              />
            </label>
            <label className="text-[12px] text-[#AAB8D0]">
              File format
              <select
                value={reader}
                onChange={(e) => setReader(e.target.value)}
                className="mt-1 w-full rounded-lg border border-[rgba(100,150,220,0.2)] bg-[rgba(5,11,24,0.8)] px-2 py-1.5 text-sm text-[#F5F8FF]"
              >
                {['json', 'xml', 'braces', 'indented', 'block'].map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </label>
            <label className="text-[12px] text-[#AAB8D0]">
              Signature ({reader === 'json' ? 'JSONPath' : 'regex'}, one per line)
              <textarea
                value={signature}
                onChange={(e) => setSig(e.target.value)}
                rows={2}
                className="mt-1 w-full rounded-lg border border-[rgba(100,150,220,0.2)] bg-[rgba(5,11,24,0.8)] px-2 py-1.5 font-mono text-[12px] text-[#F5F8FF]"
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
          <div className="border-b border-[rgba(100,150,220,0.12)] p-4">
            <h4 className="text-sm font-bold text-[#F5F8FF]">
              Unrecognised settings — {queue.data.length}
            </h4>
            <p className="mt-0.5 text-[12px] text-[#8FA0BC]">
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
                  className="space-y-2 border-b border-[rgba(100,150,220,0.08)] px-4 py-3 last:border-0"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[12.5px] text-[#F5F8FF]">{cand.name}</span>
                    {cand.kind === 'keys' && <Badge variant="info">table keys</Badge>}
                    <span className="text-[11px] text-[#65738B]">
                      {cand.occurrences.toLocaleString()}×
                    </span>
                    {cand.status === 'APPROVED' && <Badge variant="success">approved</Badge>}
                    {cand.sample_values.length > 0 && (
                      <span className="font-mono text-[11px] text-[#8FA0BC]">
                        e.g. {cand.sample_values.slice(0, 3).join(', ')}
                      </span>
                    )}
                  </div>
                  {cand.evidence?.raw && (
                    <code className="block break-all rounded-lg bg-[rgba(5,11,24,0.8)] px-2 py-1 font-mono text-[11.5px] text-[#DDE7F7]">
                      {cand.evidence.raw}
                    </code>
                  )}
                  {cand.suggested_field && (
                    <p className="text-[12px] text-[#AAB8D0]">
                      AI suggests <span className="font-mono text-[#2D8CFF]">{cand.suggested_field}</span>{' '}
                      <span className="text-[#65738B]">
                        ({cand.suggestion_score.toFixed(0)} confidence, {cand.suggested_from})
                      </span>
                    </p>
                  )}
                  <div className="flex flex-wrap items-center gap-2">
                    <input
                      list="ncsa-fields"
                      value={picked}
                      onChange={(e) => setChoice((m) => ({ ...m, [cand.name]: e.target.value }))}
                      placeholder="choose the field this setting means"
                      className="min-w-[18rem] flex-1 rounded-lg border border-[rgba(100,150,220,0.2)] bg-[rgba(5,11,24,0.8)] px-2 py-1.5 font-mono text-[12px] text-[#F5F8FF]"
                    />
                    <button
                      onClick={() => approve(cand)}
                      disabled={busy !== null || !picked || !meta || !approver.trim() || !vendorReady}
                      className="flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-[#1677FF] to-[#2D8CFF] px-3 py-1.5 text-[12px] font-semibold text-white disabled:opacity-40"
                    >
                      <Check className="h-3.5 w-3.5" />
                      {busy === cand.name ? 'Checking the corpus…' : 'Approve'}
                    </button>
                    <button
                      onClick={() => reject(cand)}
                      disabled={busy !== null || !approver.trim()}
                      className="flex items-center gap-1.5 rounded-lg border border-[rgba(100,150,220,0.25)] px-3 py-1.5 text-[12px] font-semibold text-[#AAB8D0] disabled:opacity-40"
                    >
                      <X className="h-3.5 w-3.5" />
                      Reject
                    </button>
                  </div>
                  {picked && !meta && (
                    <p className="text-[11.5px] text-[#F5B82E]">
                      Not a schema field. Pick one from the list.
                    </p>
                  )}
                  {meta && (
                    <p className="text-[11.5px] text-[#65738B]">
                      {meta.type} field ·{' '}
                      {meta.controls.length
                        ? `read by ${meta.controls.join(', ')}`
                        : 'no control reads it yet (identity or inventory)'}
                    </p>
                  )}
                  {keysMismatch && (
                    <p className="text-[11.5px] text-[#F5B82E]">
                      This setting is a table; its keys will be read as a list. Choose a
                      list-typed field.
                    </p>
                  )}
                  {verdict && (
                    <div
                      className={`rounded-lg border p-2 text-[12px] ${
                        verdict.ok
                          ? 'border-[rgba(50,214,168,0.3)] bg-[rgba(50,214,168,0.07)] text-[#9FE9D3]'
                          : 'border-[rgba(245,184,46,0.3)] bg-[rgba(245,184,46,0.07)] text-[#F5D58A]'
                      }`}
                    >
                      <strong>{verdict.ok ? 'Learned. ' : 'Not learned. '}</strong>
                      {verdict.text}
                      {verdict.ok && ' Re-assess to apply it.'}
                      {verdict.alert && (
                        <span className="block">
                          The corpus pass rate rose. That is what a poisoned mapping looks
                          like too -- worth a second look.
                        </span>
                      )}
                      {verdict.detail?.map((d) => (
                        <span key={d} className="block font-mono text-[11px]">
                          {d}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </Card>
      )}

      <Card variant="default" className="flex flex-wrap items-center justify-between gap-3 p-4">
        <p className="max-w-2xl text-[12.5px] text-[#AAB8D0]">
          Re-assess runs this same file again with everything learned so far. No
          restart and no redeploy: the next assessment simply reads the learned
          mappings.
        </p>
        <button
          onClick={runReassess}
          disabled={reBusy}
          className="flex items-center gap-2 rounded-xl border border-[rgba(80,150,255,0.35)] px-4 py-2 text-sm font-semibold text-[#2D8CFF] disabled:opacity-50"
        >
          <RefreshCw className={`h-4 w-4 ${reBusy ? 'animate-spin' : ''}`} />
          {reBusy ? 'Re-assessing…' : 'Re-assess with what was learned'}
        </button>
        {reErr && <p className="w-full text-[12px] text-[#F5B82E]">{reErr}</p>}
        {after && (
          <div className="w-full rounded-xl border border-[rgba(50,214,168,0.3)] bg-[rgba(50,214,168,0.06)] p-3 text-[12.5px] text-[#DDE7F7]">
            <strong>{after.supported ? 'Now assessable. ' : 'Still not assessable. '}</strong>
            Coverage {c.coverage ? `${c.coverage.assessed_pct}%` : 'none'} →{' '}
            {after.coverage.assessed_pct}% · score{' '}
            {after.coverage.score_pct === null ? '—' : `${after.coverage.score_pct}%`} ·{' '}
            {after.coverage.controls_decided} controls decided.
            <button
              onClick={() => navigate(`/assessments/${after.assessment_id}`)}
              className="ml-2 font-semibold text-[#2D8CFF] hover:underline"
            >
              Open the re-assessed device →
            </button>
          </div>
        )}
      </Card>
    </div>
  );
};
