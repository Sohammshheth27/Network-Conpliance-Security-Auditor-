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
    'w-full rounded-xl bg-[rgba(11,21,40,0.6)] border border-[rgba(100,150,220,0.2)] px-3 py-2 text-xs text-[#F5F8FF] focus:outline-none focus:border-[#1677FF]';

  return (
    <Card variant="default" className="p-6">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-3 text-left"
      >
        <div className="w-10 h-10 rounded-2xl bg-[rgba(22,119,255,0.15)] border border-[rgba(80,150,255,0.3)] flex items-center justify-center text-[#2D8CFF]">
          <Terminal className="w-5 h-5" />
        </div>
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-bold text-[#F5F8FF]">
            Or collect from a live device
          </h3>
          <p className="text-[11.5px] text-[#8FA0BC]">
            SSH, read-only show commands only. Credentials are used once and never stored.
          </p>
        </div>
        {open ? (
          <ChevronDown className="w-4 h-4 text-[#8FA0BC]" />
        ) : (
          <ChevronRight className="w-4 h-4 text-[#8FA0BC]" />
        )}
      </button>

      {open && (
        <div className="mt-5 space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <label className="sm:col-span-2 text-[11px] text-[#AAB8D0]">
              Host
              <input
                className={field}
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="10.0.0.1 or fw01.example.net"
                autoComplete="off"
              />
            </label>
            <label className="text-[11px] text-[#AAB8D0]">
              Port
              <input
                className={field}
                type="number"
                min={1}
                max={65535}
                value={port}
                onChange={(e) => setPort(Number(e.target.value) || 22)}
              />
            </label>
            <label className="text-[11px] text-[#AAB8D0]">
              Platform
              <select
                className={field}
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
            <label className="text-[11px] text-[#AAB8D0]">
              Driver
              <select
                className={field}
                value={driver}
                onChange={(e) => setDriver(e.target.value)}
              >
                <option value="netmiko">netmiko</option>
                {prof?.napalm && <option value="napalm">napalm ({prof.napalm})</option>}
              </select>
            </label>
            <label className="text-[11px] text-[#AAB8D0]">
              Username
              <input
                className={field}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="off"
              />
            </label>
            <label className="text-[11px] text-[#AAB8D0]">
              Password
              <input
                className={field}
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
              />
            </label>
            {platform.startsWith('cisco') && (
              <label className="text-[11px] text-[#AAB8D0]">
                Enable secret (optional)
                <input
                  className={field}
                  type="password"
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  autoComplete="new-password"
                />
              </label>
            )}
          </div>

          <label className="block text-[11px] text-[#AAB8D0]">
            Keep monitoring
            <select
              className={field}
              value={monitorEvery}
              onChange={(e) => setMonitorEvery(Number(e.target.value))}
            >
              <option value={0}>No — collect once</option>
              <option value={60}>Every hour — alert on drift</option>
              <option value={360}>Every 6 hours — alert on drift</option>
              <option value={1440}>Daily — alert on drift</option>
            </select>
            {monitorEvery > 0 && (
              <span className="mt-1 block text-[11px] text-[#8FA0BC]">
                The password is stored encrypted so the engine can log in again;
                use a read-only account. Scheduling runs when the engine is started
                with NCSA_MONITOR=1.
              </span>
            )}
          </label>

          {prof && (
            <div className="rounded-xl border border-[rgba(100,150,220,0.15)] bg-[rgba(14,27,50,0.6)] p-3 text-[11.5px] text-[#AAB8D0]">
              <span className="flex items-center gap-2 font-semibold text-[#F5F8FF]">
                <KeyRound className="w-3.5 h-3.5" /> Exactly what will be sent
              </span>
              <code className="mt-1 block font-mono text-[#32D6A8]">
                {driver === 'napalm'
                  ? `napalm get_config(retrieve='running')`
                  : prof.commands.join('  ·  ')}
              </code>
              <span className="mt-1 block">
                The pack is still chosen by fingerprinting what comes back; if it
                does not match {prof.platform}, the report says so.
              </span>
            </div>
          )}

          <div className="flex justify-end">
            <Button
              variant="primary"
              disabled={!ready}
              className="rounded-full px-6 py-3 font-semibold text-sm flex items-center gap-2"
              onClick={run}
            >
              {running ? (
                <>
                  <Cpu className="w-4 h-4 animate-spin text-white" />
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
