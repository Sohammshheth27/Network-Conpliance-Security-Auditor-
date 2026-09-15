import { useState, type FC } from 'react';
import { useSearchParams } from 'react-router-dom';
import { GraduationCap } from 'lucide-react';
import { Card } from '../components/ui/Card';
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

  // Default to a device that cannot be assessed yet: that is where teaching
  // matters most.
  const selected =
    picked ||
    list.data?.find((a) => a.score_pct === null)?.assessment_id ||
    list.data?.[0]?.assessment_id ||
    '';

  return (
    <div className="space-y-6">
      <div className="flex items-start gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[rgba(22,119,255,0.15)] text-[#2D8CFF]">
          <GraduationCap className="h-5 w-5" />
        </div>
        <div>
          <span className="mb-1 block text-[11px] font-bold uppercase tracking-widest text-[#2D8CFF]">
            Interactive training
          </span>
          <h1 className="text-3xl font-semibold tracking-tight text-[#F5F8FF]">Training</h1>
          <p className="mt-1 max-w-3xl text-sm text-[#AAB8D0]">
            Map settings the engine does not recognise to the security baseline.
            Every approval must pass the regression gate, is attributed to the
            person who made it, and takes effect on the next assessment without a
            redeploy.
          </p>
        </div>
      </div>

      {learned.data && (
        <Card variant="panel" className="flex flex-wrap items-center gap-3 p-4">
          <span className="text-xl font-bold text-[#F5F8FF]">{learned.data.total}</span>
          <span className="text-[12px] text-[#8FA0BC]">mappings learned</span>
          {learned.data.platforms.map((p) => (
            <Badge key={p.platform} variant={p.new_vendor ? 'warning' : 'outline'}>
              {p.platform} · {p.count}
              {p.new_vendor ? ' · taught from scratch' : ''}
            </Badge>
          ))}
        </Card>
      )}

      {list.loading && <Loading label="Loading assessments" />}
      {list.error && <ErrorPanel error={list.error} onRetry={list.reload} />}
      {list.data && list.data.length === 0 && (
        <Empty label="Upload a configuration in New Audit first." />
      )}

      {list.data && list.data.length > 0 && (
        <>
          <label className="block text-[12px] text-[#AAB8D0]">
            Device
            <select
              value={selected}
              onChange={(e) => setPicked(e.target.value)}
              className="mt-1 block w-full max-w-xl rounded-xl border border-[rgba(100,150,220,0.2)] bg-[rgba(5,11,24,0.8)] px-3 py-2 text-sm text-[#F5F8FF]"
            >
              {list.data.map((a) => (
                <option key={a.assessment_id} value={a.assessment_id}>
                  {a.device} · {a.vendor}
                  {a.score_pct === null ? ' · not yet assessable' : ` · ${a.assessed_pct}% coverage`}
                </option>
              ))}
            </select>
          </label>
          {selected && (
            <TrainingWorkbench
              key={selected}
              id={selected}
              onReassessed={() => {
                list.reload();
                learned.reload();
              }}
            />
          )}
        </>
      )}
    </div>
  );
};

export default Training;
