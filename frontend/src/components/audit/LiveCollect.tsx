import { useState, type FC } from 'react';
import { useNavigate } from 'react-router-dom';
import { Terminal, KeyRound, Cpu, ChevronDown, ChevronRight } from 'lucide-react';

import { Card } from '../ui/Card';
import { Button } from '../ui/Button';
import { ErrorPanel } from '../ui/States';
import { api, ApiError, type CollectProfile } from '../../lib/api';
import { useApi } from '../../lib/useApi';

/**
 * Live collection over SSH. Read-only by construction: the engine sends only
 * the fixed show commands listed for the platform, and they are displayed
 * here before anything is sent. Credentials are used for one session and are
 * cleared from this form after every attempt, successful or not.
 */
const LiveCollect: FC<{ redact: boolean; frameworks: string[] }> = ({
  redact,
  frameworks,
}) => {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const { data: profiles } = useApi<CollectProfile[]>(() => api.collectProfiles(), []);

  const [host, setHost] = useState('');
  const [port, setPort] = useState(22);
  const [platform, setPlatform] = useState('');
  const [driver, setDriver] = useState('netmiko');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [secret, setSecret] = useState('');
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  // 0 = collect once. Otherwise the engine re-collects on this interval and
  // alerts when a score drops; the password is stored encrypted for that.
  const [monitorEvery, setMonitorEvery] = useState(0);

  const prof = profiles?.find((p) => p.platform === platform);
  const ready = !!(host.trim() && platform && username && password && !running);

  const run = async () => {
    if (!ready) return;
    setRunning(true);
    setError(null);
    try {
      const request = {
        host: host.trim(),
        port,
        platform,
        driver,
        username,
        password,
        secret: secret || undefined,
        redact,
        frameworks: frameworks.length ? frameworks : null,
      };
      const [a] = await api.collect(request);
      if (monitorEvery > 0) {
        await api.createMonitor({ ...request, interval_minutes: monitorEvery });
      }
      navigate(`/assessments/${a.assessment_id}`);
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, String(e)));
    } finally {
      // Never keep a credential in memory longer than the one attempt.
      setPassword('');
      setSecret('');
      setRunning(false);
    }
  };

  const field =
    'w-full rounded-lg bg-[var(--color-pebble)] border border-[var(--color-hairline)] px-3 py-2 text-sm text-[var(--color-ink-navy)] focus:outline-none focus:border-[var(--color-signal-blue)] focus:ring-1 focus:ring-[var(--color-signal-blue)]';

  return (
    <Card variant="default" className="p-6">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-3 text-left hover:opacity-80 transition-opacity"
      >
        <div className="w-10 h-10 rounded-xl bg-[var(--color-pebble)] flex items-center justify-center text-[var(--color-signal-blue)]">
          <Terminal className="w-5 h-5" />
        </div>
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold text-[var(--color-ink-navy)]">
            Or collect from a live device
          </h3>
          <p className="text-xs text-[var(--color-slate-gray)] mt-0.5">
            SSH, read-only show commands only. Credentials are used once and never stored.
          </p>
        </div>
        {open ? (
          <ChevronDown className="w-4 h-4 text-[var(--color-slate-gray)]" />
        ) : (
          <ChevronRight className="w-4 h-4 text-[var(--color-slate-gray)]" />
        )}
      </button>

      {open && (
        <div className="mt-6 space-y-4 pt-4 border-t border-[var(--color-hairline)]">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <label className="sm:col-span-2 text-xs text-[var(--color-slate-gray)]">
              Host
              <input
                className={`${field} mt-1.5`}
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="10.0.0.1 or fw01.example.net"
                autoComplete="off"
              />
            </label>
            <label className="text-xs text-[var(--color-slate-gray)]">
              Port
              <input
                className={`${field} mt-1.5`}
                type="number"
                min={1}
                max={65535}
                value={port}
                onChange={(e) => setPort(Number(e.target.value) || 22)}
              />
            </label>
            <label className="text-xs text-[var(--color-slate-gray)]">
              Platform
              <select
                className={`${field} mt-1.5`}
                value={platform}
                onChange={(e) => {
                  setPlatform(e.target.value);
                  setDriver('netmiko');
                }}
              >
                <option value="">Choose…</option>
                {profiles?.map((p) => (
                  <option key={p.platform} value={p.platform}>
                    {p.platform}
                  </option>
                ))}
              </select>
            </label>
            <label className="text-xs text-[var(--color-slate-gray)]">
              Driver
              <select
                className={`${field} mt-1.5`}
                value={driver}
                onChange={(e) => setDriver(e.target.value)}
              >
                <option value="netmiko">netmiko</option>
                {prof?.napalm && <option value="napalm">napalm ({prof.napalm})</option>}
              </select>
            </label>
            <label className="text-xs text-[var(--color-slate-gray)]">
              Username
              <input
                className={`${field} mt-1.5`}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="off"
              />
            </label>
            <label className="text-xs text-[var(--color-slate-gray)]">
              Password
              <input
                className={`${field} mt-1.5`}
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
              />
            </label>
            {platform.startsWith('cisco') && (
              <label className="text-xs text-[var(--color-slate-gray)]">
                Enable secret (optional)
                <input
                  className={`${field} mt-1.5`}
                  type="password"
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  autoComplete="new-password"
                />
              </label>
            )}
          </div>

          <label className="block text-xs text-[var(--color-slate-gray)] pt-2">
            Keep monitoring
            <select
              className={`${field} mt-1.5`}
              value={monitorEvery}
              onChange={(e) => setMonitorEvery(Number(e.target.value))}
            >
              <option value={0}>No — collect once</option>
              <option value={60}>Every hour — alert on drift</option>
              <option value={360}>Every 6 hours — alert on drift</option>
              <option value={1440}>Daily — alert on drift</option>
            </select>
            {monitorEvery > 0 && (
              <span className="mt-2 block text-xs text-[var(--color-slate-gray)] italic">
                The password is stored encrypted so the engine can log in again;
                use a read-only account. Scheduling runs when the engine is started
                with NCSA_MONITOR=1.
              </span>
            )}
          </label>

          {prof && (
            <div className="rounded-lg border border-[var(--color-hairline)] bg-[var(--color-cloud)] p-4 text-xs text-[var(--color-slate-gray)] mt-4">
              <span className="flex items-center gap-2 font-semibold text-[var(--color-ink-navy)]">
                <KeyRound className="w-4 h-4 text-[var(--color-signal-blue)]" /> Exactly what will be sent
              </span>
              <code className="mt-2 block font-mono text-[var(--color-signal-blue)] bg-white p-2 rounded border border-[var(--color-hairline)]">
                {driver === 'napalm'
                  ? `napalm get_config(retrieve='running')`
                  : prof.commands.join('  ·  ')}
              </code>
              <span className="mt-2 block">
                The pack is still chosen by fingerprinting what comes back; if it
                does not match <span className="font-semibold text-[var(--color-ink-navy)]">{prof.platform}</span>, the report says so.
              </span>
            </div>
          )}

          <div className="flex justify-end pt-4">
            <Button
              variant="primary"
              disabled={!ready}
              className="rounded-lg px-6 py-2.5 font-semibold text-sm flex items-center gap-2"
              onClick={run}
            >
              {running ? (
                <>
                  <Cpu className="w-4 h-4 animate-spin" />
                  <span>Collecting…</span>
                </>
              ) : (
                <span>Collect and assess</span>
              )}
            </Button>
          </div>

          {error && <ErrorPanel error={error} onRetry={ready ? run : undefined} />}
        </div>
      )}
    </Card>
  );
};

export default LiveCollect;
