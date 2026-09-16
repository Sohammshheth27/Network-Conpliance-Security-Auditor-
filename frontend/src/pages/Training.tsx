import { useState, type FC } from 'react';
import { useSearchParams } from 'react-router-dom';
import { GraduationCap } from 'lucide-react';
import { Badge } from '../components/ui/Badge';
import { Empty, ErrorPanel, Loading } from '../components/ui/States';
import { TrainingWorkbench } from '../components/training/TrainingWorkbench';
import { api } from '../lib/api';
import { useApi } from '../lib/useApi';

/**
 * Training -- where an administrator teaches the engine a format it does not
 * know. A top-level page rather than a sub-tab, because the problem statement
 * makes this loop the heart of the product.
 */
const Training: FC = () => {
  const list = useApi(() => api.assessments(), []);
  const learned = useApi(() => api.learnedSummary(), []);
  const [params] = useSearchParams();
  const [picked, setPicked] = useState<string>(params.get('id') ?? '');

  // Default to a device that has 0% coverage: that is where teaching matters most.
  const selected =
    picked ||
    list.data?.find((a) => a.assessed_pct === 0)?.assessment_id ||
    list.data?.[0]?.assessment_id ||
    '';

  return (
    <div className="space-y-6">
      <div className="text-center sm:text-left">
        <span className="mb-1 block text-[11px] font-bold uppercase tracking-widest text-[var(--color-signal-blue)]">
          INTERACTIVE TRAINING
        </span>
        <h1 className="text-3xl font-semibold tracking-tight text-[var(--color-ink-navy)]">
          Training
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-[var(--color-slate-gray)]">
          Map settings the engine does not recognise to the security baseline.
          Every approval must pass the regression gate, is attributed to the
          person who made it, and takes effect on the next assessment without a
          redeploy.
        </p>
      </div>

      {learned.data && (
        <div className="flex flex-wrap items-center gap-3 p-4 bg-white border border-[var(--color-hairline)] rounded-xl shadow-sm">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[rgba(0,107,255,0.1)] text-[var(--color-signal-blue)] border border-[rgba(0,107,255,0.2)]">
            <GraduationCap className="h-5 w-5" />
          </div>
          <span className="text-xl font-bold text-[var(--color-ink-navy)] ml-1">{learned.data.total}</span>
          <span className="text-xs font-medium text-[var(--color-slate-gray)] mr-2">mappings learned</span>
          <div className="h-6 w-px bg-[var(--color-hairline)] mx-1" />
          {learned.data.platforms.map((p) => (
            <Badge key={p.platform} variant={p.new_vendor ? 'warning' : 'outline'}>
              {p.platform} · {p.count}
              {p.new_vendor ? ' · taught from scratch' : ''}
            </Badge>
          ))}
        </div>
      )}

      {list.loading && <Loading label="Loading assessments" />}
      {list.error && <ErrorPanel error={list.error} onRetry={list.reload} />}
      {list.data && list.data.length === 0 && (
        <Empty label="Upload a configuration in New Audit first." />
      )}

      {list.data && list.data.length > 0 && (
        <>
          <label className="block text-xs font-semibold text-[var(--color-slate-gray)] mb-2 mt-8">
            SELECT DEVICE FOR TRAINING
            <select
              value={selected}
              onChange={(e) => setPicked(e.target.value)}
              className="mt-2 block w-full max-w-xl rounded-lg border border-[var(--color-hairline)] bg-white px-3 py-2.5 text-sm text-[var(--color-ink-navy)] focus:outline-none focus:border-[var(--color-signal-blue)] focus:ring-1 focus:ring-[var(--color-signal-blue)] shadow-sm font-medium"
            >
              {list.data.map((a) => (
                <option key={a.assessment_id} value={a.assessment_id}>
                  {a.device} · {a.vendor}
                  {a.assessed_pct === 0 ? ' · not yet assessable' : ` · ${a.assessed_pct}% coverage`}
                </option>
              ))}
            </select>
          </label>
          
          {selected && (
            <div className="pt-2">
              <TrainingWorkbench
                key={selected}
                id={selected}
                onReassessed={() => {
                  list.reload();
                  learned.reload();
                }}
              />
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default Training;
