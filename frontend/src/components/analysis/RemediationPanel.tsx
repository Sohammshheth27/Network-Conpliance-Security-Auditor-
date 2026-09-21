import { useMemo, useState, type FC } from 'react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Empty, ErrorPanel, Loading } from '../ui/States';
import { api, download, type HardenedResponse, type RemediationStep } from '../../lib/api';
import { useApi } from '../../lib/useApi';

/**
 * Deliverable 4c in the console: the ordered fix sequence for this device.
 *
 * The engine has built this plan since the beginning and nothing in the UI ever
 * called it -- `api.remediation` existed and no component used it, so the
 * commands reached the PDF report and never the screen.
 *
 * Three things this shows that a bare command list does not, because all three
 * are the difference between a script an engineer runs and one they discard:
 *
 *  - WHAT IT COSTS YOU. A step that disables the protocol you are connected
 *    over carries its warning next to the commands, not in a footnote.
 *  - WHAT WAS HELD BACK. Steps that would sever the only management path are
 *    excluded from the script and listed separately, with the reason.
 *  - WHAT IS NOT FIXED. Failing controls with no recorded fix are named. An
 *    unlisted gap reads as a solved one, and on the reference device that is
 *    16 of 30 findings.
 */
export const RemediationPanel: FC<{ id: string }> = ({ id }) => {
  const { data, loading, error, reload } = useApi(() => api.remediation(id), [id], {
    cacheKey: `remediation-${id}`,
  });

  // The script is offered as a file as well as on screen: it is meant to be
  // reviewed in an editor, not copied out of a browser pane.
  const url = useMemo(
    () =>
      data?.script
        ? URL.createObjectURL(new Blob([data.script], { type: 'text/plain' }))
        : null,
    [data?.script],
  );

  if (loading) return <Loading label="Building the remediation plan" />;
  if (error) return <ErrorPanel error={error} onRetry={reload} />;
  if (!data) return null;

  const { steps, deferred, unavailable, lockout_checked: checked } = data;

  if (!steps.length && !deferred.length && !unavailable.length)
    return <Empty label="Nothing to remediate: no failing control on this device has a recorded fix, and none is missing one." />;

  return (
    <div className="space-y-4">
      {/* The guard reports whether it ran. Without this, a plan with no
          warnings looks identical to one that was never checked. */}
      {!checked && (
        <Card variant="default" className="border-l-4 border-l-[#b45309] p-4">
          <p className="text-sm font-bold text-[#b45309]">The lockout check did not run</p>
          <p className="mt-1 text-xs text-[var(--color-slate-gray)]">
            The device model was unavailable, so no step below has been checked
            against the management transports this device actually has enabled.
            A step that disables the protocol you are connected over will not be
            flagged here. Verify each step by hand before running it.
          </p>
        </Card>
      )}

      <Card variant="default" className="flex flex-wrap items-center justify-between gap-3 p-4">
        <div>
          <h3 className="text-sm font-bold text-[var(--color-ink-navy)]">
            Remediation — {steps.length} step{steps.length === 1 ? '' : 's'}
          </h3>
          <p className="mt-0.5 max-w-3xl text-xs text-[var(--color-slate-gray)]">
            Ordered so nothing locks you out: the replacement is created and
            enabled before the insecure setting is removed. Nothing here is
            applied to the device — this is the sequence to review and run.
          </p>
        </div>
        {url && (
          <a
            href={url}
            download={`remediation-${id}.txt`}
            className="rounded-xl bg-[var(--color-signal-blue)] px-3 py-2 text-xs font-semibold text-white"
          >
            Download script
          </a>
        )}
      </Card>

      <HardenedConfig id={id} />

      {data.rollback_command && (
        <Card variant="default" className="p-4">
          <p className="text-xs font-bold text-[var(--color-ink-navy)]">
            Safety net — run this first
          </p>
          <pre className="mt-2 overflow-x-auto rounded-lg bg-[var(--color-pebble)] p-3 font-mono text-xs text-[var(--color-ink-navy)]">
            {data.rollback_command}
          </pre>
          <p className="mt-1.5 text-xs text-[var(--color-slate-gray)]">{data.rollback_note}</p>
        </Card>
      )}

      {steps.map((s, i) => (
        <StepCard key={`${s.control_id}-${i}`} step={s} />
      ))}

      {deferred.length > 0 && (
        <Card variant="default" className="p-4">
          <h4 className="text-sm font-bold text-[var(--color-ink-navy)]">
            Held back — {deferred.length}
          </h4>
          <p className="mt-0.5 text-xs text-[var(--color-slate-gray)]">
            These would sever the only management path to this device, so they
            are deliberately excluded from the script above. Apply them through
            console access or a maintenance window.
          </p>
          <div className="mt-3 space-y-2">
            {deferred.map((s, i) => (
              <div key={`${s.control_id}-${i}`} className="rounded-lg border border-[var(--color-hairline)] p-3">
                <p className="font-mono text-xs text-[var(--color-ink-navy)]">{s.control_id}</p>
                <p className="mt-0.5 text-xs text-[var(--color-slate-gray)]">
                  {s.lockout_warning || s.title}
                </p>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Named, never silently dropped: an unlisted gap reads as a solved one. */}
      {unavailable.length > 0 && (
        <Card variant="default" className="p-4">
          <h4 className="text-sm font-bold text-[var(--color-ink-navy)]">
            Not remediated — {unavailable.length}
          </h4>
          <p className="mt-0.5 text-xs text-[var(--color-slate-gray)]">
            These controls fail and have no recorded fix for this platform. The
            findings stand; only the suggested command sequence is missing.
          </p>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {unavailable.map((c) => (
              <span
                key={c}
                className="rounded-md border border-[var(--color-hairline)] px-2 py-1 font-mono text-[11px] text-[var(--color-slate-gray)]"
              >
                {c}
              </span>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
};

const BAND: Record<string, string> = {
  CRITICAL: '#be123c',
  HIGH: '#be123c',
  MEDIUM: '#b45309',
  LOW: '#476788',
};

const StepCard: FC<{ step: RemediationStep }> = ({ step: s }) => (
  <Card variant="default" className="p-4">
    <div className="flex flex-wrap items-center gap-2">
      {s.risk_band && (
        <Badge style={{ color: BAND[s.risk_band] ?? '#476788' }}>{s.risk_band}</Badge>
      )}
      <span className="font-mono text-xs text-[var(--color-slate-gray)]">{s.control_id}</span>
      <span className="text-sm font-semibold text-[var(--color-ink-navy)]">{s.title}</span>
    </div>

    {/* The caution sits ABOVE the commands. An engineer who reads only the
        code block must not miss the reason the step can cut them off. */}
    {s.lockout_warning && (
      <p className="mt-2 rounded-lg border-l-4 border-l-[#be123c] bg-[var(--color-pebble)] px-3 py-2 text-xs text-[#be123c]">
        <strong>Caution.</strong> {s.lockout_warning}
      </p>
    )}

    <pre className="mt-2 overflow-x-auto rounded-lg bg-[var(--color-pebble)] p-3 font-mono text-xs text-[var(--color-ink-navy)]">
      {(s.commands ?? []).join('\n')}
    </pre>

    {s.verify && (
      <p className="mt-1.5 font-mono text-[11px] text-[var(--color-slate-gray)]">
        verify: {s.verify}
      </p>
    )}
  </Card>
);

/**
 * The hardened configuration, and the compliance it MEASURES.
 *
 * Fetched on demand, not with the panel: the engine writes the corrected
 * configuration and assesses it again, so the before/after is the number this
 * tool would report on the fixed device rather than an estimate of it. That
 * costs a full re-assessment, which is not something to spend on every tab
 * switch.
 */
const HardenedConfig: FC<{ id: string }> = ({ id }) => {
  const [data, setData] = useState<HardenedResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState('');

  const run = async () => {
    setBusy(true);
    setFailed('');
    try {
      setData(await api.hardened(id));
    } catch (e) {
      setFailed(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const before = data?.before?.score_pct ?? null;
  const after = data?.after?.score_pct ?? null;

  return (
    <Card variant="default" className="p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h4 className="text-sm font-bold text-[var(--color-ink-navy)]">
            Hardened configuration
          </h4>
          <p className="mt-0.5 max-w-3xl text-xs text-[var(--color-slate-gray)]">
            This device's own configuration with the provable failures
            corrected. Only records a finding cites are rewritten — settings
            that pass are untouched, and settings the engine could not read are
            never changed.
          </p>
        </div>
        <button
          onClick={run}
          disabled={busy}
          className="rounded-xl border border-[var(--color-hairline)] px-3 py-2 text-xs font-semibold text-[var(--color-ink-navy)] disabled:opacity-50"
        >
          {busy ? 'Measuring…' : data ? 'Re-measure' : 'Generate and measure'}
        </button>
      </div>

      {failed && (
        <p className="mt-3 text-xs text-[#be123c]">{failed}</p>
      )}

      {data && !data.supported && (
        <p className="mt-3 text-xs text-[var(--color-slate-gray)]">{data.note}</p>
      )}

      {data?.supported && (
        <>
          {before !== null && after !== null && (
            <div className="mt-3 flex flex-wrap items-end gap-6 rounded-xl bg-[var(--color-pebble)] p-4">
              <Score label="Before" value={before} />
              <span className="pb-1 text-lg text-[var(--color-slate-gray)]">→</span>
              <Score label="After" value={after} accent="#047857" />
              <div className="pb-1">
                <p className="text-[11px] uppercase tracking-wider text-[var(--color-mist-gray)]">
                  Measured
                </p>
                <p className="text-sm font-bold text-[#047857]">
                  +{(data.score_delta ?? 0).toFixed(1)} points
                </p>
              </div>
              <div className="pb-1 text-xs text-[var(--color-slate-gray)]">
                {data.changes.length} setting{data.changes.length === 1 ? '' : 's'} rewritten
                {' · '}
                {data.refused.length} not changed
              </div>
            </div>
          )}

          {/* UNKNOWN is shown deliberately: it should NOT move, and seeing it
              hold still is how you know nothing unreadable was touched. */}
          {data.before?.states && data.after?.states && (
            <div className="mt-3 overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-left text-[11px] uppercase tracking-wider text-[var(--color-mist-gray)]">
                    <th className="py-1.5 font-semibold">State</th>
                    <th className="py-1.5 font-semibold">Before</th>
                    <th className="py-1.5 font-semibold">After</th>
                  </tr>
                </thead>
                <tbody>
                  {['PASS', 'FAIL', 'PARTIAL', 'UNKNOWN'].map((s) => (
                    <tr key={s} className="border-t border-[var(--color-hairline)]">
                      <td className="py-1.5 font-mono text-[var(--color-ink-navy)]">{s}</td>
                      <td className="py-1.5 text-[var(--color-slate-gray)]">
                        {data.before?.states?.[s] ?? 0}
                      </td>
                      <td className="py-1.5 text-[var(--color-ink-navy)]">
                        {data.after?.states?.[s] ?? 0}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {data.changes.length > 0 && (
            <div className="mt-3 overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-left text-[11px] uppercase tracking-wider text-[var(--color-mist-gray)]">
                    <th className="py-1.5 font-semibold">Control</th>
                    <th className="py-1.5 font-semibold">Setting</th>
                    <th className="py-1.5 font-semibold">Before</th>
                    <th className="py-1.5 font-semibold">After</th>
                    <th className="py-1.5 font-semibold">Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {data.changes.map((c) => (
                    <tr key={c.record} className="border-t border-[var(--color-hairline)]">
                      <td className="py-1.5 font-mono text-[var(--color-slate-gray)]">{c.control_id}</td>
                      <td className="py-1.5 font-mono text-[var(--color-ink-navy)]">{c.key}</td>
                      <td className="py-1.5 font-mono text-[var(--color-slate-gray)]">
                        {c.before || '(empty)'}
                      </td>
                      <td className="py-1.5 font-mono text-[#047857]">{c.after.slice(0, 40)}</td>
                      <td className="py-1.5 font-mono text-[11px] text-[var(--color-mist-gray)]">
                        {c.record}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {data.changes.length > 0 && (
            <div className="mt-3 flex flex-wrap items-center gap-3">
              {/* A plain <a href> to an API route is fetched by the browser
                  with no Authorization header, so it 401s for a signed-in
                  operator. `download()` makes the request through fetch with
                  the session attached and then saves the blob. */}
              <button
                onClick={() =>
                  download(`/assessment/${id}/hardened.conf`, `hardened-${id}.exp`)
                }
                className="rounded-xl bg-[var(--color-signal-blue)] px-3 py-2 text-xs font-semibold text-white"
              >
                Download hardened configuration
              </button>
              <p className="text-xs text-[var(--color-slate-gray)]">
                Carries this device's real addressing. Import is unverified —
                test it on a sandbox appliance before a live device.
              </p>
            </div>
          )}
        </>
      )}
    </Card>
  );
};

const Score: FC<{ label: string; value: number; accent?: string }> = ({
  label,
  value,
  accent,
}) => (
  <div>
    <p className="text-[11px] uppercase tracking-wider text-[var(--color-mist-gray)]">
      {label}
    </p>
    <p
      className="text-2xl font-bold"
      style={{ color: accent ?? 'var(--color-ink-navy)' }}
    >
      {value.toFixed(1)}%
    </p>
  </div>
);
