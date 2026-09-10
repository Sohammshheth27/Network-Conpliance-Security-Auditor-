import type { FC } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowRight, Plus, Server, ShieldCheck, Layers, Cpu } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { RadialProgress } from '../components/ui/RadialProgress';
import { Empty, ErrorPanel, Loading, StatePill } from '../components/ui/States';
import {
  api,
  coverageCaption,
  RESULT_STATES,
  vendorLabel,
  type Assessment,
  type AssessmentSummary,
} from '../lib/api';
import { useApi } from '../lib/useApi';

const Home: FC = () => {
  const navigate = useNavigate();

  const list = useApi<AssessmentSummary[]>(() => api.assessments(), []);
  const health = useApi(() => api.health(), []);

  const rows = list.data ?? [];
  const latestId = rows.length ? rows[rows.length - 1].assessment_id : null;

  // The hero gauge shows a REAL device, so it is fetched rather than summarised
  // from the list -- the list carries no counts, and inventing them would put
  // fabricated numbers on the most prominent card in the product.
  const latest = useApi<Assessment>(() => api.assessment(latestId!), [latestId], {
    enabled: Boolean(latestId),
  });

  return (
    <div className="space-y-6">
      <div className="flex select-none flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <span className="mb-1 block text-[11px] font-bold uppercase tracking-widest text-[#2D8CFF]">
            NCSA SECURITY WORKBENCH
          </span>
          <h1 className="text-3xl font-semibold tracking-tight text-[#F5F8FF] lg:text-4xl">
            Security Overview
          </h1>
          <p className="mt-1 text-xs text-[#AAB8D0] sm:text-sm">
            Network and firewall compliance posture across the devices assessed
            in this session.
          </p>
        </div>

        <Button
          variant="primary"
          className="flex items-center gap-2 rounded-full px-5 py-2.5 text-sm font-semibold"
          onClick={() => navigate('/new-audit')}
        >
          <Plus className="h-4 w-4" />
          <span>New Audit</span>
        </Button>
      </div>

      {list.loading && <Loading label="Connecting to the engine" />}
      {list.error && <ErrorPanel error={list.error} onRetry={list.reload} />}

      {list.data && rows.length === 0 && (
        <Card variant="default" className="p-10 text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-[rgba(22,119,255,0.15)] text-[#2D8CFF]">
            <Server className="h-7 w-7" />
          </div>
          <h3 className="text-lg font-bold text-[#F5F8FF]">
            No assessments yet
          </h3>
          <p className="mx-auto mt-1 max-w-md text-sm text-[#AAB8D0]">
            Upload a firewall or switch configuration and the engine will
            fingerprint it, select a mapping pack, and evaluate it against 81
            controls.
          </p>
          <Button
            variant="primary"
            className="mt-5 rounded-full px-5 py-2.5 text-sm font-semibold"
            onClick={() => navigate('/new-audit')}
          >
            Run the first audit
          </Button>
        </Card>
      )}

      {rows.length > 0 && (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
          {/* --------------------------------------------- hero: latest device */}
          <Card variant="glow" className="lg:col-span-2">
            {latest.loading && <Loading label="Loading latest assessment" />}
            {latest.error && <ErrorPanel error={latest.error} />}
            {latest.data && (
              <>
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F8FF]">
                      SECURITY POSTURE
                    </h3>
                    <span className="text-[11px] text-[#65738B]">
                      LATEST ASSESSMENT ·{' '}
                      {vendorLabel(latest.data.identity.vendor)}{' '}
                      {latest.data.identity.os}
                    </span>
                  </div>
                  <Badge variant="info">
                    {latest.data.identity.hostname ||
                      latest.data.identity.source_file}
                  </Badge>
                </div>

                <div className="mt-5 flex flex-wrap items-center gap-8">
                  {/* Each gauge is labelled with what it actually shows. The
                      component defaults both to "COMPLIANCE SCORE", which
                      would print that caption over the coverage number. */}
                  <div className="text-center">
                    <RadialProgress
                      value={latest.data.coverage.score_pct}
                      size={112}
                      label="COMPLIANCE"
                      sublabel="SCORE"
                    />
                  </div>
                  <div className="text-center">
                    <RadialProgress
                      value={latest.data.coverage.assessed_pct}
                      size={112}
                      label="DEVICE"
                      sublabel="COVERAGE"
                    />
                  </div>
                </div>

                {/* The caption is generated in one place so no page can render
                    a score without the coverage that qualifies it. */}
                <p className="mt-4 text-[13px] text-[#AAB8D0]">
                  {coverageCaption(latest.data.coverage)}
                </p>

                <div className="mt-4 flex flex-wrap gap-1.5">
                  {RESULT_STATES.filter(
                    (s) => (latest.data!.counts[s] ?? 0) > 0,
                  ).map((s) => (
                    <span key={s} className="flex items-center gap-1.5">
                      <StatePill state={s} />
                      <span className="text-[12px] font-semibold text-[#F5F8FF]">
                        {latest.data!.counts[s]}
                      </span>
                    </span>
                  ))}
                </div>

                <button
                  onClick={() =>
                    navigate(`/assessments/${latest.data!.assessment_id}`)
                  }
                  className="mt-5 flex items-center gap-1.5 text-xs font-semibold text-[#2D8CFF] transition-colors hover:text-[#5AA5FF]"
                >
                  Open assessment
                  <ArrowRight className="h-3.5 w-3.5" />
                </button>
              </>
            )}
          </Card>

          {/* ------------------------------------------------- engine snapshot */}
          <Card variant="default">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F8FF]">
              ENGINE
            </h3>
            {health.loading && <Loading label="Reading engine" />}
            {health.error && <ErrorPanel error={health.error} />}
            {health.data && (
              <div className="mt-4 space-y-3">
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[rgba(50,214,168,0.15)] text-[#32D6A8]">
                    <Cpu className="h-4 w-4" />
                  </div>
                  <div>
                    <span className="block text-lg font-bold text-[#F5F8FF]">
                      {health.data.platforms_parsed.length}
                    </span>
                    <span className="text-[11px] text-[#8FA0BC]">
                      platforms parsed
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[rgba(22,119,255,0.15)] text-[#2D8CFF]">
                    <Layers className="h-4 w-4" />
                  </div>
                  <div>
                    <span className="block text-lg font-bold text-[#F5F8FF]">
                      {health.data.graph_analyses.platforms.length}
                    </span>
                    <span className="text-[11px] text-[#8FA0BC]">
                      with a policy object graph
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[rgba(245,184,46,0.15)] text-[#F5B82E]">
                    <ShieldCheck className="h-4 w-4" />
                  </div>
                  <div>
                    <span className="block text-lg font-bold text-[#F5F8FF]">
                      {health.data.assessments}
                    </span>
                    <span className="text-[11px] text-[#8FA0BC]">
                      assessments in session
                    </span>
                  </div>
                </div>
              </div>
            )}
          </Card>
        </div>
      )}

      {rows.length > 0 && (
        <Card variant="default" className="overflow-hidden p-0">
          <div className="flex items-center justify-between border-b border-[rgba(100,150,220,0.12)] p-4">
            <h3 className="text-sm font-bold text-[#F5F8FF]">
              Assessed devices
            </h3>
            <button
              onClick={() => navigate('/assessments')}
              className="text-xs font-semibold text-[#2D8CFF] hover:text-[#5AA5FF]"
            >
              View all
            </button>
          </div>
          {rows.length === 0 ? (
            <Empty label="Nothing assessed yet." />
          ) : (
            rows
              .slice()
              .reverse()
              .slice(0, 6)
              .map((r) => (
                <button
                  key={r.assessment_id}
                  onClick={() => navigate(`/assessments/${r.assessment_id}`)}
                  className="flex w-full items-center justify-between gap-4 border-b border-[rgba(100,150,220,0.08)] px-4 py-3 text-left transition-colors last:border-0 hover:bg-[rgba(22,119,255,0.06)]"
                >
                  <div className="flex min-w-0 items-center gap-3">
                    <Server className="h-4 w-4 shrink-0 text-[#65738B]" />
                    <span className="truncate font-mono text-[13px] text-[#F5F8FF]">
                      {r.device}
                    </span>
                    <Badge variant="info">{vendorLabel(r.vendor)}</Badge>
                  </div>
                  <div className="flex shrink-0 items-center gap-4">
                    <span className="text-[13px] font-bold text-[#F5F8FF]">
                      {r.score_pct}%
                    </span>
                    <span className="text-[12px] text-[#8FA0BC]">
                      {r.assessed_pct}% cov
                    </span>
                    <ArrowRight className="h-4 w-4 text-[#65738B]" />
                  </div>
                </button>
              ))
          )}
        </Card>
      )}
    </div>
  );
};

export default Home;
