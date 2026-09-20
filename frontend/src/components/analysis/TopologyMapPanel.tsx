import { useEffect, useMemo, useState, type FC } from 'react';
import { Download, EyeOff } from 'lucide-react';
import { Card } from '../ui/Card';
import { ErrorPanel, Loading } from '../ui/States';
import { api } from '../../lib/api';
import { useApi } from '../../lib/useApi';

/**
 * 2-D topology of the device: zones, LANs, WLANs, uplinks, VPN sites.
 *
 * The SVG is drawn by the engine so this panel, the PNG export and the report
 * show the same picture. It is displayed through <img>, not injected as
 * markup: the figure contains names taken from the configuration, which is
 * untrusted input, and an <img> cannot execute anything inside it.
 *
 * Redaction is on by default -- WAN addresses are real public IPs and tunnel
 * names are usually customer sites.
 */
export const TopologyMapPanel: FC<{ id: string }> = ({ id }) => {
  const [redact, setRedact] = useState(true);
  const svg = useApi(() => api.topologySvg(id, redact), [id, redact]);
  // An object URL for the <img> and the download link, derived from the SVG
  // text; the effect only releases it when the figure changes.
  const url = useMemo(
    () =>
      svg.data
        ? URL.createObjectURL(new Blob([svg.data], { type: 'image/svg+xml' }))
        : null,
    [svg.data],
  );
  useEffect(
    () => () => {
      if (url) URL.revokeObjectURL(url);
    },
    [url],
  );

  return (
    <div className="space-y-4">
      <Card variant="default" className="flex flex-wrap items-center justify-between gap-3 p-4">
        <p className="max-w-3xl text-[12.5px] text-[var(--color-slate-gray)]">
          Drawn from the configuration, not live discovery: it shows the zones,
          subnets, uplinks and VPN sites the device is configured for. Dashed
          zones exist in the policy with nothing assigned. Red arrows are
          zone-to-zone any/any allows.
        </p>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setRedact((r) => !r)}
            className="flex items-center gap-2 rounded-xl border border-[var(--color-hairline)] px-3 py-2 text-xs font-semibold text-[var(--color-ink-navy)]"
          >
            <EyeOff className="h-3.5 w-3.5" />
            {redact ? 'Show real addresses & names' : 'Redact public IPs & site names'}
          </button>
          {url && (
            <a
              href={url}
              download={`topology-${id}${redact ? '-redacted' : ''}.svg`}
              className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-[var(--color-signal-blue)] to-[var(--color-signal-blue)] px-3 py-2 text-xs font-semibold text-white"
            >
              <Download className="h-3.5 w-3.5" />
              Download SVG
            </a>
          )}
        </div>
      </Card>

      {svg.loading && <Loading label="Drawing topology" />}
      {svg.error && <ErrorPanel error={svg.error} onRetry={svg.reload} />}
      {url && !svg.loading && (
        <div className="overflow-x-auto rounded-2xl border border-[var(--color-hairline)]">
          <img src={url} alt="Device topology derived from configuration" className="block min-w-[1100px] w-full" />
        </div>
      )}
    </div>
  );
};
