import { type FC } from 'react';
import { Cpu, Layers, Radio, CheckCircle, ShieldCheck } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { ErrorPanel, Loading } from '../components/ui/States';
import { api, vendorLabel } from '../lib/api';
import { useApi } from '../lib/useApi';

const Settings: FC = () => {
  const health = useApi(() => api.health(), [], { cacheKey: 'health' });
  const platforms = useApi(() => api.platforms(), [], { cacheKey: 'platforms' });

  const graphPlatforms = new Set(
    (health.data?.graph_analyses.platforms ?? []).map((p) => p.toLowerCase()),
  );

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

      <Card variant="default" className="p-6 bg-white">
        <h3 className="mb-1 text-sm font-bold uppercase tracking-wider text-[var(--color-ink-navy)]">
          Design & Appearance Standard
        </h3>
        <p className="mb-4 text-[12.5px] font-medium text-[var(--color-slate-gray)]">
          NCSA Editorial Design System aligned to approved visual references.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="p-4 rounded-xl bg-[var(--color-cloud)] border border-[var(--color-hairline)]">
            <span className="text-[11px] font-bold uppercase text-[var(--color-slate-gray)] block mb-1">
              Visual Theme
            </span>
            <div className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-[#10B981]" />
              <span className="text-sm font-bold text-[var(--color-ink-navy)]">
                Editorial Light
              </span>
            </div>
            <span className="text-[11px] text-[var(--color-slate-gray)] mt-1 block">
              Cool marble background (#f8f9fb)
            </span>
          </div>

          <div className="p-4 rounded-xl bg-[var(--color-cloud)] border border-[var(--color-hairline)]">
            <span className="text-[11px] font-bold uppercase text-[var(--color-slate-gray)] block mb-1">
              Typography Standard
            </span>
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-[var(--color-signal-blue)]" />
              <span className="text-sm font-bold text-[var(--color-ink-navy)]">
                Inter & Manrope
              </span>
            </div>
            <span className="text-[11px] text-[var(--color-slate-gray)] mt-1 block">
              Proportional hierarchy & tabular numerals
            </span>
          </div>

          <div className="p-4 rounded-xl bg-[var(--color-cloud)] border border-[var(--color-hairline)]">
            <span className="text-[11px] font-bold uppercase text-[var(--color-slate-gray)] block mb-1">
              Navigation Geometry
            </span>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-black" />
              <span className="text-sm font-bold text-[var(--color-ink-navy)]">
                Fixed Black Rail
              </span>
            </div>
            <span className="text-[11px] text-[var(--color-slate-gray)] mt-1 block">
              Rounded right geometry, squircle active items
            </span>
          </div>
        </div>
      </Card>

      <Card variant="default" className="p-6 bg-white">
        <h3 className="mb-1 text-sm font-bold uppercase tracking-wider text-[var(--color-ink-navy)]">
          Engine
        </h3>
        <p className="mb-4 text-[12.5px] font-medium text-[var(--color-slate-gray)]">
          Read live from <code className="font-mono">/health</code>. The
          capability list comes from the code at runtime, so it cannot drift
          from what the build actually does.
        </p>

        {health.loading && <Loading label="Contacting engine" />}
        {health.error && (
          <ErrorPanel error={health.error} onRetry={health.reload} />
        )}

        {health.data && (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant={health.data.ok ? 'success' : 'critical'}>
                <Radio className="h-3 w-3" />
                {health.data.ok ? 'Online' : 'Unhealthy'}
              </Badge>
              <Badge variant="outline">
                {health.data.assessments} assessments in session
              </Badge>
            </div>

            <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="rounded-xl border border-[var(--color-hairline)] bg-[var(--color-cloud)] p-3">
                <div className="flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-[var(--color-signal-blue)]" />
                  <span className="text-[11px] font-bold uppercase tracking-wider text-[var(--color-slate-gray)]">
                    Graph analyses
                  </span>
                </div>
                <p className="mt-1.5 text-[12.5px] font-medium text-[var(--color-ink-navy)]">
                  {health.data.graph_analyses.capabilities
                    .map((c) => c.replace(/_/g, ' '))
                    .join(' · ')}
                </p>
                <p className="mt-1 text-[12px] text-[var(--color-slate-gray)]">
                  on {health.data.graph_analyses.platforms.join(', ')}
                </p>
              </div>
              <div className="rounded-xl border border-[var(--color-hairline)] bg-[var(--color-cloud)] p-3">
                <div className="flex items-center gap-2">
                  <Layers className="h-4 w-4 text-[#10B981]" />
                  <span className="text-[11px] font-bold uppercase tracking-wider text-[var(--color-slate-gray)]">
                    Platforms parsed
                  </span>
                </div>
                <p className="mt-1.5 text-[12.5px] font-medium text-[var(--color-ink-navy)]">
                  {health.data.platforms_parsed.length} platforms across all
                  loaded packs
                </p>
              </div>
            </div>

            <p className="mt-3 rounded-xl border border-[var(--color-hairline)] bg-[var(--color-pebble)] p-3 text-[12px] font-medium leading-relaxed text-[var(--color-slate-gray)]">
              {health.data.graph_analyses.note}
            </p>
          </>
        )}
      </Card>

      <Card variant="default" className="overflow-hidden p-0 bg-white">
        <div className="border-b border-[var(--color-hairline)] p-4 bg-[var(--color-cloud)]">
          <h3 className="text-sm font-bold uppercase tracking-wider text-[var(--color-ink-navy)]">
            Mapping packs
          </h3>
          <p className="mt-0.5 text-[12px] font-medium text-[var(--color-slate-gray)]">
            A new vendor is a YAML file, not a code change. Packs are data.
          </p>
        </div>

        {platforms.loading && <Loading label="Loading packs" />}
        {platforms.error && (
          <div className="p-5">
            <ErrorPanel error={platforms.error} onRetry={platforms.reload} />
          </div>
        )}

        {platforms.data && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--color-hairline)] text-left text-[11px] font-bold uppercase tracking-wider text-[var(--color-slate-gray)]">
                  <th className="px-4 py-2.5">Vendor</th>
                  <th className="px-4 py-2.5">Platform</th>
                  <th className="px-4 py-2.5">Reader</th>
                  <th className="px-4 py-2.5">Mappings</th>
                  <th className="px-4 py-2.5">Object graph</th>
                </tr>
              </thead>
              <tbody>
                {platforms.data.map((p) => {
                  const hasGraph = [...graphPlatforms].some((g) =>
                    p.platform.toLowerCase().includes(g.split(' ')[0]),
                  );
                  return (
                    <tr
                      key={p.platform + p.vendor}
                      className="border-b border-[var(--color-hairline)] last:border-0 hover:bg-[var(--color-pebble)] transition-colors"
                    >
                      <td className="px-4 py-2.5 font-bold text-[var(--color-ink-navy)]">
                        {vendorLabel(p.vendor)}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[12px] text-[var(--color-slate-gray)]">
                        {p.platform}
                      </td>
                      <td className="px-4 py-2.5 font-medium text-[var(--color-slate-gray)]">{p.reader}</td>
                      <td className="px-4 py-2.5 font-medium text-[var(--color-ink-navy)]">
                        {p.mappings}
                      </td>
                      <td className="px-4 py-2.5">
                        <Badge variant={hasGraph ? 'success' : 'default'}>
                          {hasGraph ? 'yes' : 'parse only'}
                        </Badge>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
};

export default Settings;
