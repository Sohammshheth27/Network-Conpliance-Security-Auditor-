import { type FC } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  ArrowRight,
  GitCompare,
  Network,
  Route,
  ScrollText,
  Stamp,
  Server,
} from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Empty, ErrorPanel, Loading } from '../components/ui/States';
import { api } from '../lib/api';
import { useApi } from '../lib/useApi';

/**
 * What this build can actually do, read from the engine rather than asserted.
 *
 * `/health` publishes which analyses need a policy object graph and which
 * platforms have one. Hard-coding that list here would let the page claim a
 * capability the build does not have the moment a builder is added or removed.
 */

const GRAPH_ANALYSES = [
  {
    key: 'rule_hygiene',
    icon: Activity,
    title: 'Rule hygiene',
    blurb:
      'Dead, shadowed, redundant and over-broad policy. Unevaluable rules are reported beside the findings, because a rule we could not resolve is not a clean rule.',
  },
  {
    key: 'reachability',
    icon: Route,
    title: 'Reachability',
    blurb:
      'Would this traffic be permitted? First-match-wins, naming the rule that decided it, with a caveat when an earlier rule could not be evaluated.',
  },
  {
    key: 'recertification',
    icon: Stamp,
    title: 'Recertification',
    blurb:
      'Which rules need a human decision, and which are deletion candidates. Deletion requires three independent signals agreeing.',
  },
];

const ALWAYS_ON = [
  {
    icon: GitCompare,
    title: 'Change tracking',
    blurb:
      'Snapshot and diff. Device change and analysis change are reported separately — a pack update altering a verdict is not configuration drift.',
  },
  {
    icon: Network,
    title: 'Topology',
    blurb:
      'Interface addressing and multi-device fabric. Adjacency is inferred from shared subnets, and that caveat travels on every answer.',
  },
  {
    icon: ScrollText,
    title: 'Parser cross-check',
    blurb:
      'Two independent methods read the same device. Agreement promotes a caveat to a conclusion; disagreement is surfaced rather than resolved by preference.',
  },
];

const Analysis: FC = () => {
  const health = useApi(() => api.health(), []);
  const assessments = useApi(() => api.assessments(), []);

  const graphPlatforms = health.data?.graph_analyses.platforms ?? [];
  const rows = assessments.data ?? [];

  return (
    <div className="space-y-6">
      <div>
        <span className="mb-1 block text-[11px] font-bold uppercase tracking-widest text-[#2D8CFF]">
          NCSA ANALYSIS ENGINE
        </span>
        <h1 className="text-3xl font-semibold tracking-tight text-[#F5F8FF]">
          Analysis
        </h1>
        <p className="mt-1 text-sm text-[#AAB8D0]">
          Deeper analyses beyond control compliance. Open any assessment to run
          them.
        </p>
      </div>

      {health.loading && <Loading label="Reading engine capabilities" />}
      {health.error && (
        <ErrorPanel error={health.error} onRetry={health.reload} />
      )}

      {health.data && (
        <>
          <Card variant="default" className="p-5">
            <h3 className="text-sm font-bold text-[#F5F8FF]">
              Capability boundary
            </h3>
            <p className="mt-1 text-[12.5px] leading-relaxed text-[#AAB8D0]">
              {health.data.graph_analyses.note}
            </p>
            <div className="mt-3 flex flex-wrap gap-2">
              {graphPlatforms.map((p) => (
                <Badge key={p} variant="success">
                  {p}
                </Badge>
              ))}
              <Badge variant="outline">
                {health.data.platforms_parsed.length} platforms parsed
              </Badge>
            </div>
          </Card>

          <div>
            <h2 className="mb-3 text-sm font-bold uppercase tracking-wider text-[#F5F8FF]">
              Needs a policy object graph
            </h2>
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              {GRAPH_ANALYSES.map((a) => {
                const Icon = a.icon;
                const available = health.data!.graph_analyses.capabilities.includes(
                  a.key,
                );
                return (
                  <Card key={a.key} variant="default" className="p-5">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[rgba(22,119,255,0.15)] text-[#2D8CFF]">
                        <Icon className="h-5 w-5" />
                      </div>
                      <Badge variant={available ? 'success' : 'default'}>
                        {available ? 'Operational' : 'Unavailable'}
                      </Badge>
                    </div>
                    <h3 className="mt-3 text-base font-bold text-[#F5F8FF]">
                      {a.title}
                    </h3>
                    <p className="mt-1 text-[12.5px] leading-relaxed text-[#AAB8D0]">
                      {a.blurb}
                    </p>
                    <p className="mt-2 text-[11.5px] text-[#65738B]">
                      Available on: {graphPlatforms.join(' · ')}
                    </p>
                  </Card>
                );
              })}
            </div>
          </div>

          <div>
            <h2 className="mb-3 text-sm font-bold uppercase tracking-wider text-[#F5F8FF]">
              Available on every parsed platform
            </h2>
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              {ALWAYS_ON.map((a) => {
                const Icon = a.icon;
                return (
                  <Card key={a.title} variant="default" className="p-5">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[rgba(50,214,168,0.15)] text-[#32D6A8]">
                        <Icon className="h-5 w-5" />
                      </div>
                      <Badge variant="success">Operational</Badge>
                    </div>
                    <h3 className="mt-3 text-base font-bold text-[#F5F8FF]">
                      {a.title}
                    </h3>
                    <p className="mt-1 text-[12.5px] leading-relaxed text-[#AAB8D0]">
                      {a.blurb}
                    </p>
                  </Card>
                );
              })}
            </div>
          </div>
        </>
      )}

      <Card variant="default" className="overflow-hidden p-0">
        <div className="border-b border-[rgba(100,150,220,0.12)] p-4">
          <h3 className="text-sm font-bold text-[#F5F8FF]">
            Run an analysis on a device
          </h3>
        </div>
        {assessments.loading && <Loading label="Loading devices" />}
        {assessments.error && (
          <div className="p-5">
            <ErrorPanel error={assessments.error} onRetry={assessments.reload} />
          </div>
        )}
        {assessments.data && rows.length === 0 && (
          <Empty label="Nothing assessed yet. Upload a configuration first." />
        )}
        {rows.map((r) => (
          <Link
            key={r.assessment_id}
            to={`/assessments/${r.assessment_id}`}
            className="flex items-center justify-between gap-4 border-b border-[rgba(100,150,220,0.08)] px-4 py-3 transition-colors last:border-0 hover:bg-[rgba(22,119,255,0.06)]"
          >
            <div className="flex items-center gap-3">
              <Server className="h-4 w-4 text-[#65738B]" />
              <span className="font-mono text-[13px] text-[#F5F8FF]">
                {r.device}
              </span>
              <Badge variant="info">{r.vendor}</Badge>
            </div>
            <ArrowRight className="h-4 w-4 text-[#65738B]" />
          </Link>
        ))}
      </Card>
    </div>
  );
};

export default Analysis;
