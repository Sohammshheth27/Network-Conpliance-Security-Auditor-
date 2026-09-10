import { type FC } from 'react';
import { Cpu, Layers, Radio } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { ErrorPanel, Loading } from '../components/ui/States';
import { api, vendorLabel } from '../lib/api';
import { useApi } from '../lib/useApi';
import { ThemeToggle } from '../components/theme/ThemeToggle';

const Settings: FC = () => {
  const health = useApi(() => api.health(), []);
  const platforms = useApi(() => api.platforms(), []);

  const graphPlatforms = new Set(
    (health.data?.graph_analyses.platforms ?? []).map((p) => p.toLowerCase()),
  );

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <span className="mb-1 block text-[11px] font-bold uppercase tracking-widest text-[#2D8CFF]">
          NCSA CONFIGURATION
        </span>
        <h1 className="text-3xl font-semibold tracking-tight text-[#F5F8FF]">
          Settings
        </h1>
        <p className="mt-1 text-sm text-[#AAB8D0]">
          Engine status and the packs this build has loaded.
        </p>
      </div>

      <Card variant="default" className="p-6">
        <h3 className="mb-4 text-sm font-bold uppercase tracking-wider text-[#F5F8FF]">
          Appearance
        </h3>
        <div className="flex items-center justify-between">
          <div>
            <span className="block text-sm font-medium text-[#F5F8FF]">
              Theme
            </span>
            <span className="text-[12px] text-[#8FA0BC]">
              Light and dark are both supported.
            </span>
          </div>
          <ThemeToggle />
        </div>
      </Card>

      <Card variant="default" className="p-6">
        <h3 className="mb-1 text-sm font-bold uppercase tracking-wider text-[#F5F8FF]">
          Engine
        </h3>
        <p className="mb-4 text-[12.5px] text-[#8FA0BC]">
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
              <div className="rounded-xl border border-[rgba(100,150,220,0.14)] p-3">
                <div className="flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-[#2D8CFF]" />
                  <span className="text-[11px] uppercase tracking-wider text-[#65738B]">
                    Graph analyses
                  </span>
                </div>
                <p className="mt-1.5 text-[12.5px] text-[#AAB8D0]">
                  {health.data.graph_analyses.capabilities
                    .map((c) => c.replace(/_/g, ' '))
                    .join(' · ')}
                </p>
                <p className="mt-1 text-[12px] text-[#F5F8FF]">
                  on {health.data.graph_analyses.platforms.join(', ')}
                </p>
              </div>
              <div className="rounded-xl border border-[rgba(100,150,220,0.14)] p-3">
                <div className="flex items-center gap-2">
                  <Layers className="h-4 w-4 text-[#32D6A8]" />
                  <span className="text-[11px] uppercase tracking-wider text-[#65738B]">
                    Platforms parsed
                  </span>
                </div>
                <p className="mt-1.5 text-[12.5px] text-[#AAB8D0]">
                  {health.data.platforms_parsed.length} platforms across all
                  loaded packs
                </p>
              </div>
            </div>

            <p className="mt-3 rounded-xl border border-[rgba(100,150,220,0.14)] bg-[rgba(14,27,50,0.4)] p-3 text-[12px] leading-relaxed text-[#AAB8D0]">
              {health.data.graph_analyses.note}
            </p>
          </>
        )}
      </Card>

      <Card variant="default" className="overflow-hidden p-0">
        <div className="border-b border-[rgba(100,150,220,0.12)] p-4">
          <h3 className="text-sm font-bold uppercase tracking-wider text-[#F5F8FF]">
            Mapping packs
          </h3>
          <p className="mt-0.5 text-[12px] text-[#8FA0BC]">
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
                <tr className="border-b border-[rgba(100,150,220,0.12)] text-left text-[11px] uppercase tracking-wider text-[#65738B]">
                  <th className="px-4 py-2.5 font-semibold">Vendor</th>
                  <th className="px-4 py-2.5 font-semibold">Platform</th>
                  <th className="px-4 py-2.5 font-semibold">Reader</th>
                  <th className="px-4 py-2.5 font-semibold">Mappings</th>
                  <th className="px-4 py-2.5 font-semibold">Object graph</th>
                </tr>
              </thead>
              <tbody>
                {platforms.data.map((p) => {
                  // A platform without a graph builder still parses and still
                  // produces control findings. Saying "parse only" keeps that
                  // distinction visible instead of reading as unsupported.
                  const hasGraph = [...graphPlatforms].some((g) =>
                    p.platform.toLowerCase().includes(g.split(' ')[0]),
                  );
                  return (
                    <tr
                      key={p.platform + p.vendor}
                      className="border-b border-[rgba(100,150,220,0.08)] last:border-0"
                    >
                      <td className="px-4 py-2.5 text-[#F5F8FF]">
                        {vendorLabel(p.vendor)}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[12px] text-[#AAB8D0]">
                        {p.platform}
                      </td>
                      <td className="px-4 py-2.5 text-[#8FA0BC]">{p.reader}</td>
                      <td className="px-4 py-2.5 text-[#AAB8D0]">
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
