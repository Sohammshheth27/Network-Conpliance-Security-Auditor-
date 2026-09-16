import type { FC } from 'react';
import { Cpu, Layers, Radio } from 'lucide-react';
import { Card } from './ui/Card';
import { Badge } from './ui/Badge';
import { ErrorPanel, Loading } from './ui/States';
import { api, vendorLabel } from '../lib/api';
import { useApi } from '../lib/useApi';

export const SystemStatus: FC = () => {
  const health = useApi(() => api.health(), [], { cacheKey: 'health' });
  const platforms = useApi(() => api.platforms(), [], { cacheKey: 'platforms' });

  const graphPlatforms = new Set(
    (health.data?.graph_analyses.platforms ?? []).map((p) => p.toLowerCase()),
  );

  return (
    <div className="space-y-6 mt-12">
      <div>
        <h2 className="text-xl font-semibold tracking-tight text-[var(--color-ink-navy)]">
          Engine Capabilities & Mapping Packs
        </h2>
        <p className="mt-1 text-[12.5px] text-[var(--color-slate-gray)]">
          Read live from the engine at runtime.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8 xl:col-span-9 space-y-6">
          <Card variant="default" className="p-6 bg-white">
            <h3 className="mb-1 text-sm font-bold uppercase tracking-wider text-[var(--color-ink-navy)]">
              Engine
            </h3>
            {health.loading && <Loading label="Contacting engine" />}
            {health.error && <ErrorPanel error={health.error} onRetry={health.reload} />}

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
                      {health.data.platforms_parsed.length} platforms across all loaded packs
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
                          key={`${p.platform}-${p.vendor}-${p.reader}`}
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
      </div>
    </div>
  );
};
