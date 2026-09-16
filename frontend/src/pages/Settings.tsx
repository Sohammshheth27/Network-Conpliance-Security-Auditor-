import { useState, type FC } from 'react';
import { KeyRound } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { ErrorPanel, Loading } from '../components/ui/States';
import { api } from '../lib/api';
import { useApi } from '../lib/useApi';

/** The API token, needed only when the engine runs with NCSA_API_TOKEN set.
 *  Stored in this browser; storage may be blocked, so every access is guarded. */
const ApiAccess: FC = () => {
  const read = () => {
    try {
      return localStorage.getItem('ncsa_api_token') || '';
    } catch {
      return '';
    }
  };
  const [saved, setSaved] = useState(read() !== '');
  const [value, setValue] = useState('');
  const store = (v: string) => {
    try {
      if (v) localStorage.setItem('ncsa_api_token', v);
      else localStorage.removeItem('ncsa_api_token');
    } catch {
      /* storage unavailable: nothing to persist */
    }
    setSaved(read() !== '');
    setValue('');
  };
  return (
    <Card variant="default" className="p-6">
      <h3 className="mb-1 flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-[var(--color-ink-navy)]">
        <KeyRound className="h-4 w-4 text-[#2D8CFF]" /> API access
      </h3>
      <p className="mb-3 text-[12.5px] text-[var(--color-slate-gray)]">
        Needed only when the engine is started with <code className="font-mono">NCSA_API_TOKEN</code>.
        Without it the engine answers this machine only. The token stays in this browser.
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <input
          type="password"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={saved ? 'token saved — enter a new one to replace it' : 'API token'}
          autoComplete="off"
          className="min-w-[240px] flex-1 rounded-xl border border-[var(--color-hairline)] bg-white px-3 py-2 text-xs text-[var(--color-ink-navy)] focus:border-[#1677FF] focus:outline-none"
        />
        <button
          onClick={() => store(value.trim())}
          disabled={!value.trim()}
          className="rounded-full border border-[var(--color-hairline)] px-3 py-1.5 text-xs font-semibold text-[var(--color-ink-navy)] hover:border-[#1677FF] disabled:opacity-50"
        >
          Save
        </button>
        {saved && (
          <button
            onClick={() => store('')}
            className="rounded-full border border-[rgba(229,72,77,0.4)] px-3 py-1.5 text-xs font-semibold text-[#E5484D]"
          >
            Clear
          </button>
        )}
      </div>
    </Card>
  );
};

/** Scheduled re-collection jobs and their drift alerts. */
const Monitoring: FC = () => {
  const mon = useApi(() => api.monitors(), []);
  const [busy, setBusy] = useState('');
  const act = async (id: string, fn: (id: string) => Promise<unknown>) => {
    setBusy(id);
    try {
      await fn(id);
    } finally {
      setBusy('');
      mon.reload();
    }
  };
  const btn =
    'rounded-full border border-[var(--color-hairline)] px-2.5 py-1 text-[11px] font-semibold text-[var(--color-ink-navy)] hover:border-[#1677FF] disabled:opacity-50';
  return (
    <Card variant="default" className="p-6">
      <h3 className="mb-1 text-sm font-bold uppercase tracking-wider text-[var(--color-ink-navy)]">
        Monitoring
      </h3>
      <p className="mb-3 text-[12.5px] text-[var(--color-slate-gray)]">
        Devices re-collected on a schedule. An alert is raised when the overall
        score or any framework score drops, a control regresses, or the device
        cannot be reached. Create one from the live-collection form.
      </p>
      {mon.loading && <Loading label="Reading monitoring jobs" />}
      {mon.error && <ErrorPanel error={mon.error} onRetry={mon.reload} />}
      {mon.data && mon.data.jobs.length === 0 && (
        <p className="text-[12px] text-[var(--color-slate-gray)]">No devices are being monitored.</p>
      )}
      {mon.data && mon.data.jobs.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[12.5px]">
            <thead className="text-[10.5px] uppercase tracking-wider text-[var(--color-slate-gray)]">
              <tr>
                <th className="py-1 pr-3">Device</th>
                <th className="py-1 pr-3">Every</th>
                <th className="py-1 pr-3">Last run</th>
                <th className="py-1 pr-3">Status</th>
                <th className="py-1 pr-3 text-right">Score</th>
                <th className="py-1" />
              </tr>
            </thead>
            <tbody className="text-[var(--color-ink-navy)]">
              {mon.data.jobs.map((j) => (
                <tr key={j.job_id} className="border-t border-[rgba(100,150,220,0.1)]">
                  <td className="py-1.5 pr-3 font-mono">{j.host}</td>
                  <td className="py-1.5 pr-3">{j.interval_minutes} min</td>
                  <td className="py-1.5 pr-3 font-mono text-[11px]">{j.last_run ?? 'never'}</td>
                  <td className="py-1.5 pr-3">{j.last_status ?? '—'}</td>
                  <td className="py-1.5 pr-3 text-right">
                    {j.last_score == null ? '—' : `${j.last_score}%`}
                  </td>
                  <td className="py-1.5 text-right space-x-1">
                    <button className={btn} disabled={busy === j.job_id}
                            onClick={() => act(j.job_id, api.runMonitor)}>Run now</button>
                    <button className={btn} disabled={busy === j.job_id}
                            onClick={() => act(j.job_id, api.deleteMonitor)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {mon.data && mon.data.alerts.length > 0 && (
        <ul className="mt-4 space-y-1 text-[12px] text-[#AAB8D0]">
          {mon.data.alerts.slice(0, 20).map((a) => (
            <li key={a.alert_id}>
              <span className="font-mono text-[11px] text-[var(--color-slate-gray)]">{a.at}</span>{' '}
              <Badge variant={a.kind === 'collection_failed' ? 'warning' : 'critical'}>
                {a.kind.replace(/_/g, ' ')}
              </Badge>{' '}
              {a.detail}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
};

const Settings: FC = () => {
  return (
    <div className="max-w-5xl space-y-6">
      <div>
        <span className="mb-1 block text-[11px] font-bold uppercase tracking-widest text-[var(--color-slate-gray)]">
          NCSA CONFIGURATION
        </span>
        <h1 className="text-3xl font-semibold tracking-tight text-[var(--color-ink-navy)]">
          Settings
        </h1>
        <p className="mt-1 text-sm text-[var(--color-slate-gray)]">
          Engine status, active design standards, and loaded mapping packs.
        </p>
      </div>



      <ApiAccess />

      <Monitoring />

    </div>
  );
};

export default Settings;
