import { Fragment, useMemo, useState, type FC } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { 
  ArrowLeft, 
  Terminal, 
  ChevronRight,
  ShieldCheck,
  FileCode,
  Sliders,
  AlertTriangle,
  ShieldAlert,
  AlertCircle,
  Play,
  FileText,
  Loader2
} from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Empty, ErrorPanel, Loading } from '../components/ui/States';
import {
  api,
  download,
  failuresBySeverity,
  vendorLabel,
  type Assessment,
  type Finding,
  type Severity,
} from '../lib/api';
import { useApi } from '../lib/useApi';
import { AnalysisTabs } from '../components/analysis/AnalysisTabs';

type DetailTab = 'overview' | 'execution' | 'findings' | 'compliance' | 'analysis';

/** The framework an organisation aligns to, or all of them. */
type FrameworkKey = 'all' | 'nist_800_53' | 'iso_27001' | 'cis_ids' | 'stig_ids';

const FRAMEWORK_TABS: { key: FrameworkKey; label: string }[] = [
  { key: 'all', label: 'All frameworks' },
  { key: 'nist_800_53', label: 'NIST 800-53' },
  { key: 'iso_27001', label: 'ISO 27001' },
  { key: 'cis_ids', label: 'CIS' },
  { key: 'stig_ids', label: 'STIG' },
];

const CITATIONS = [
  { key: 'nist_800_53', label: 'NIST' },
  { key: 'iso_27001', label: 'ISO 27001' },
  { key: 'cis_ids', label: 'CIS' },
  { key: 'stig_ids', label: 'STIG' },
] as const;

/** How many findings cite one framework. Takes the key already narrowed away
 *  from 'all', because TypeScript drops that narrowing inside a callback. */
const countCiting = (rows: Finding[], key: Exclude<FrameworkKey, 'all'>) =>
  rows.filter((f) => (f.frameworks?.[key]?.length ?? 0) > 0).length;

/** A value as the engine reported it. Null and empty are shown as a dash
 *  rather than "null": the finding's reason says what the absence means. */
const show = (v: unknown): string => {
  if (v === null || v === undefined || v === '') return '—';
  return typeof v === 'object' ? JSON.stringify(v) : String(v);
};

const AssessmentDetail: FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<DetailTab>('overview');
  const [pdfError, setPdfError] = useState<any>(null);
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [findingFilter, setFindingFilter] = useState<'all' | Severity>('all');
  const [frameworkFilter, setFrameworkFilter] = useState<FrameworkKey>('all');
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  const { data, loading, error, reload } = useApi<Assessment>(
    () => api.assessment(id!),
    [id],
    { enabled: Boolean(id), cacheKey: `assessment-${id}` },
  );

  /** Failing now, and badly enough that nobody should have to be looking at
   *  the right framework to see it. An any/any rule or an unauthenticated
   *  management service is an incident waiting to happen whichever catalogue
   *  an organisation aligns to, so these survive the framework filter. */
  const isUrgent = (f: Finding) =>
    (f.severity === 'critical' || f.severity === 'high') &&
    (f.state === 'FAIL' || f.state === 'PARTIAL');

  const citesSelected = (f: Finding) => {
    if (frameworkFilter === 'all') return true;
    return (f.frameworks?.[frameworkFilter]?.length ?? 0) > 0;
  };

  const findings = useMemo(() => {
    if (!data) return [];
    return data.findings.filter(
      (f) =>
        (findingFilter === 'all' || f.severity === findingFilter) &&
        (citesSelected(f) || isUrgent(f)),
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, findingFilter, frameworkFilter]);

  if (loading) return <Loading label="Loading assessment" />;
  if (error) return <ErrorPanel error={error} onRetry={reload} />;
  if (!data) return <Empty label="No such assessment found." />;

  const { identity, coverage, records } = data;
  // Each framework judged against its OWN requirements, which is why there is
  // no single number here any more: the same device is 37% to NIST and 37% to
  // ISO because those catalogues group the evidence differently.
  //
  // A null score is not a zero. It means the framework publishes nothing for
  // this platform -- there is no CIS benchmark or DISA STIG for SonicOS -- and
  // rendering that as 0% would report a failure the device never had. Scored
  // frameworks sort first so the card leads with real numbers.
  const frameworkScores = [...(data.framework_coverage ?? [])].sort(
    (a, b) =>
      Number(a.framework_score_pct === null) -
        Number(b.framework_score_pct === null) ||
      a.name.localeCompare(b.name),
  );
  const someFrameworkUnscored = frameworkScores.some(
    (f) => f.framework_score_pct === null,
  );
  const bySeverity = failuresBySeverity(data.findings);
  const totalFindingsCount = data.findings.length;
  const assessmentDisplayId = id?.startsWith('NCSA') ? id : `NCSA-2026-${id?.slice(0, 4).toUpperCase() || '0014'}`;
  const deviceName = identity.hostname || identity.source_file || 'Device';
  const vendorClean = vendorLabel(identity.vendor);
  const platformClean = identity.os || identity.platform || 'Platform';

  const tabs: { id: DetailTab; label: string }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'execution', label: 'Execution' },
    { id: 'findings', label: `Findings (${totalFindingsCount})` },
    { id: 'compliance', label: 'Compliance' },
    { id: 'analysis', label: 'Deep Analysis' },
  ];

  return (
    <div className="space-y-6 max-w-[1440px] mx-auto">
      {/* 1. Top Back Navigation */}
      <div>
        <button
          onClick={() => navigate('/assessments')}
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-[var(--color-slate-gray)] transition-colors hover:text-[var(--color-ink-navy)]"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          <span>Assessments</span>
        </button>
      </div>

      {/* 2. Header Area */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[var(--color-ink-navy)]">
              {assessmentDisplayId}
            </h1>
            <span className="px-2.5 py-0.5 text-[11px] font-semibold rounded-full bg-blue-50 text-blue-700 border border-blue-200">
              Completed
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs font-medium text-[var(--color-slate-gray)] mt-1.5">
            <span className="font-bold text-[var(--color-ink-navy)]">{deviceName}</span>
            <span>|</span>
            <span>{vendorClean} · {platformClean}</span>
          </div>
        </div>
      </div>

      {/* 3. Pill Tabs Bar */}
      <div className="flex flex-wrap items-center gap-2 pt-1 pb-2">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            className={`px-4 py-1.5 rounded-full text-xs font-semibold transition-all ${
              activeTab === t.id
                ? 'bg-[#0a0a0a] text-white shadow-xs'
                : 'bg-[var(--color-pebble)] text-[var(--color-slate-gray)] hover:text-[var(--color-ink-navy)] hover:bg-[var(--color-cloud)]'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* 4. MAIN WORKSPACE LAYOUT */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* LEFT COLUMN (Cols 8) */}
        <div className="lg:col-span-8 space-y-6">
          
          {activeTab === 'overview' && (
            <Card className="p-6 bg-white border border-[var(--color-hairline)]">
              <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--color-slate-gray)] mb-4">
                Assessment Overview
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
                {/* Framework Scores */}
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <ShieldCheck className="w-4 h-4 text-[var(--color-signal-blue)]" />
                    <span className="text-xs font-semibold text-[var(--color-slate-gray)]">Framework Scores</span>
                  </div>
                  <div className="space-y-2 mt-1.5">
                    {frameworkScores.map((f) => (
                      <div key={f.framework}>
                        <div className="flex items-baseline justify-between gap-2">
                          <span className="text-[11px] text-[var(--color-slate-gray)] truncate">
                            {f.name}
                          </span>
                          <span className="text-sm font-bold text-[var(--color-ink-navy)] shrink-0">
                            {f.framework_score_pct === null
                              ? '—'
                              : `${Math.round(f.framework_score_pct)}%`}
                          </span>
                        </div>
                        <div className="w-full h-1.5 bg-[var(--color-pebble)] rounded-full mt-1 overflow-hidden">
                          {f.framework_score_pct !== null && (
                            <div
                              className="h-full bg-[var(--color-signal-blue)] rounded-full"
                              style={{ width: `${Math.round(f.framework_score_pct)}%` }}
                            />
                          )}
                        </div>
                        {f.framework_score_pct !== null && (
                          <span className="text-[10px] text-[var(--color-mist-gray)] block mt-0.5">
                            {f.requirements_met} / {f.requirements} requirements met
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                  {someFrameworkUnscored && (
                    <span className="text-[10px] text-[var(--color-mist-gray)] block mt-2">
                      — publishes no requirements for this platform
                    </span>
                  )}
                </div>

                {/* Configuration Coverage */}
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <FileCode className="w-4 h-4 text-emerald-600" />
                    <span className="text-xs font-semibold text-[var(--color-slate-gray)]">Configuration Coverage</span>
                  </div>
                  <div className="text-2xl font-bold text-[var(--color-ink-navy)]">
                    {Math.round(coverage.assessed_pct)}%
                  </div>
                  <div className="w-full h-1.5 bg-[var(--color-pebble)] rounded-full mt-2 overflow-hidden">
                    <div 
                      className="h-full bg-emerald-500 rounded-full" 
                      style={{ width: `${Math.round(coverage.assessed_pct)}%` }}
                    />
                  </div>
                </div>

                {/* Total Findings */}
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <AlertTriangle className="w-4 h-4 text-rose-500" />
                    <span className="text-xs font-semibold text-[var(--color-slate-gray)]">Total Findings</span>
                  </div>
                  <div className="text-2xl font-bold text-[var(--color-ink-navy)]">
                    {totalFindingsCount}
                  </div>
                  <div className="flex items-center gap-2 text-[11px] font-semibold mt-2">
                    <span className="flex items-center gap-1 text-rose-600">
                      <span className="w-2 h-2 rounded-full bg-rose-500"></span> {bySeverity.critical || 0}
                    </span>
                    <span className="flex items-center gap-1 text-orange-600">
                      <span className="w-2 h-2 rounded-full bg-orange-500"></span> {bySeverity.high || 0}
                    </span>
                    <span className="flex items-center gap-1 text-amber-600">
                      <span className="w-2 h-2 rounded-full bg-amber-500"></span> {bySeverity.medium || 0}
                    </span>
                    <span className="flex items-center gap-1 text-slate-500">
                      <span className="w-2 h-2 rounded-full bg-slate-400"></span> {bySeverity.low || 0}
                    </span>
                  </div>
                </div>

                {/* Device Info */}
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <Sliders className="w-4 h-4 text-[var(--color-slate-gray)]" />
                    <span className="text-xs font-semibold text-[var(--color-slate-gray)]">Device Info</span>
                  </div>
                  <div className="text-base font-bold text-[var(--color-ink-navy)] truncate">
                    {deviceName}
                  </div>
                  <span className="text-[11px] text-[var(--color-slate-gray)] block mt-0.5 truncate">
                    {vendorClean} · {platformClean}
                  </span>
                  {identity.model && (
                    <span className="text-[10px] text-[var(--color-mist-gray)] block mt-1 font-mono truncate">
                      {identity.model}
                    </span>
                  )}
                </div>
              </div>
            </Card>
          )}

          {activeTab === 'overview' && (
            <div className="flex flex-col sm:flex-row gap-4 mt-6">
              <Button 
                variant="primary"
                size="lg"
                className="flex-1 flex items-center justify-center gap-2 rounded-xl text-sm font-semibold shadow-sm"
                onClick={() => navigate('/new-audit')}
              >
                <Play className="w-4 h-4 fill-current" />
                Re-run Assessment
              </Button>
              <Button 
                variant="outline"
                size="lg"
                disabled={downloadingPdf}
                className="flex-1 flex items-center justify-center gap-2 rounded-xl text-sm font-semibold shadow-sm bg-white hover:bg-[var(--color-cloud)]"
                onClick={async () => {
                  setPdfError(null);
                  setDownloadingPdf(true);
                  try {
                    await download(api.reportUrl(id!), `NCSA_Report_${id}.pdf`);
                  } catch (e: any) {
                    setPdfError(e);
                  } finally {
                    setDownloadingPdf(false);
                  }
                }}
              >
                {downloadingPdf ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <FileText className="w-4 h-4" />
                )}
                {downloadingPdf ? 'Generating PDF...' : 'Download PDF Report'}
              </Button>
            </div>
          )}

          {activeTab === 'overview' && pdfError && (
            <div className="mt-4">
              <ErrorPanel error={pdfError} onRetry={() => setPdfError(null)} />
            </div>
          )}

          {activeTab === 'overview' && (
            <Card className="p-6 bg-white border border-[var(--color-hairline)] mt-6">
              <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--color-slate-gray)] mb-5">
                Activity Log
              </h3>
              <div className="space-y-5">
                <div className="flex gap-4 relative">
                  <div className="absolute left-[3px] top-[14px] bottom-[-20px] w-px bg-[var(--color-hairline)]" />
                  <div className="w-2 h-2 rounded-full bg-[var(--color-signal-blue)] mt-1.5 shrink-0 z-10 shadow-[0_0_0_4px_white]" />
                  <div>
                    <div className="text-sm font-bold text-[var(--color-ink-navy)] mb-0.5">Assessment Completed</div>
                    <div className="text-xs text-[var(--color-slate-gray)] font-medium">Generated {totalFindingsCount} findings and compliance mapping.</div>
                  </div>
                </div>
                <div className="flex gap-4 relative">
                  <div className="absolute left-[3px] top-[14px] bottom-[-20px] w-px bg-[var(--color-hairline)]" />
                  <div className="w-2 h-2 rounded-full bg-[var(--color-slate-gray)] mt-1.5 shrink-0 z-10 shadow-[0_0_0_4px_white]" />
                  <div>
                    <div className="text-sm font-bold text-[var(--color-ink-navy)] mb-0.5">Rules Applied</div>
                    <div className="text-xs text-[var(--color-slate-gray)] font-medium">Mapped against CIS, NIST, and PCI-DSS frameworks.</div>
                  </div>
                </div>
                <div className="flex gap-4 relative">
                  <div className="w-2 h-2 rounded-full bg-[var(--color-slate-gray)] mt-1.5 shrink-0 z-10 shadow-[0_0_0_4px_white]" />
                  <div>
                    <div className="text-sm font-bold text-[var(--color-ink-navy)] mb-0.5">Configuration Parsed</div>
                    <div className="text-xs text-[var(--color-slate-gray)] font-medium">Successfully extracted interface and routing data.</div>
                  </div>
                </div>
              </div>
            </Card>
          )}

          {activeTab === 'execution' && (
            <Card className="p-6 bg-white border border-[var(--color-hairline)]">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-bold text-[var(--color-ink-navy)]">
                  Audit Execution Log
                </h3>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-3 gap-6">
                <div>
                  <span className="text-[11px] text-[var(--color-slate-gray)] block mb-1 uppercase font-bold">Source Records</span>
                  <span className="text-xl font-bold text-[var(--color-ink-navy)]">{records.source_records}</span>
                </div>
                <div>
                  <span className="text-[11px] text-[var(--color-slate-gray)] block mb-1 uppercase font-bold">Parsed Records</span>
                  <span className="text-xl font-bold text-[var(--color-ink-navy)]">{records.parsed_records}</span>
                </div>
                <div>
                  <span className="text-[11px] text-[var(--color-slate-gray)] block mb-1 uppercase font-bold">Mapped to Schema</span>
                  <span className="text-xl font-bold text-emerald-600">{records.mapped_to_schema}</span>
                </div>
                <div>
                  <span className="text-[11px] text-[var(--color-slate-gray)] block mb-1 uppercase font-bold">Unreadable Records</span>
                  <span className="text-xl font-bold text-rose-500">{records.unreadable_records}</span>
                </div>
                <div>
                  <span className="text-[11px] text-[var(--color-slate-gray)] block mb-1 uppercase font-bold">Parsed, not mapped</span>
                  <span className="text-xl font-bold text-amber-500">{records.parsed_not_mapped}</span>
                </div>
                <div>
                  <span className="text-[11px] text-[var(--color-slate-gray)] block mb-1 uppercase font-bold">Security Unmapped</span>
                  <span className="text-xl font-bold text-orange-500">{records.security_relevant_unmapped}</span>
                </div>
              </div>
            </Card>
          )}

          {activeTab === 'findings' && (
            <Card className="p-0 overflow-hidden bg-white border border-[var(--color-hairline)] shadow-sm">
              <div className="p-4 border-b border-[var(--color-hairline)] flex flex-wrap items-center justify-between gap-3">
                <h3 className="text-sm font-bold text-[var(--color-ink-navy)]">
                  Findings ({findings.length})
                </h3>

                {/* Severity filter tabs */}
                <div className="flex items-center gap-1.5 text-xs font-semibold">
                  {(['all', 'critical', 'high', 'medium', 'low'] as const).map((sev) => {
                    const count = sev === 'all' ? totalFindingsCount : bySeverity[sev] || 0;
                    return (
                      <button
                        key={sev}
                        onClick={() => setFindingFilter(sev)}
                        className={`px-3 py-1 rounded-full text-xs font-semibold transition-colors ${
                          findingFilter === sev
                            ? 'bg-[#0a0a0a] text-white'
                            : 'bg-[var(--color-cloud)] text-[var(--color-slate-gray)] hover:bg-[var(--color-pebble)] hover:text-[var(--color-ink-navy)]'
                        }`}
                      >
                        {sev.charAt(0).toUpperCase() + sev.slice(1)} ({count})
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* The framework an organisation aligns to. Everything it cites
                  is shown; so is anything failing badly, whatever it cites. */}
              <div className="px-4 py-3 border-b border-[var(--color-hairline)] flex flex-wrap items-center gap-2">
                <span className="text-[11px] font-bold uppercase tracking-wider text-[var(--color-slate-gray)] mr-1">
                  Align to
                </span>
                {FRAMEWORK_TABS.map((t) => {
                  const count =
                    t.key === 'all'
                      ? data.findings.length
                      : countCiting(data.findings, t.key);
                  return (
                    <button
                      key={t.key}
                      onClick={() => setFrameworkFilter(t.key)}
                      className={`px-3 py-1 rounded-full text-xs font-semibold transition-colors ${
                        frameworkFilter === t.key
                          ? 'bg-[var(--color-signal-blue)] text-white'
                          : 'bg-[var(--color-cloud)] text-[var(--color-slate-gray)] hover:bg-[var(--color-pebble)] hover:text-[var(--color-ink-navy)]'
                      }`}
                    >
                      {t.label} ({count})
                    </button>
                  );
                })}
                {frameworkFilter !== 'all' && (
                  <span className="text-[11px] text-[var(--color-slate-gray)]">
                    plus critical and high failures from every framework
                  </span>
                )}
              </div>

              {findings.length === 0 ? (
                <div className="p-12 text-center">
                  <ShieldCheck className="w-12 h-12 text-emerald-500 mx-auto mb-3" />
                  <h3 className="text-base font-bold text-[var(--color-ink-navy)]">No findings</h3>
                  <p className="text-sm text-[var(--color-slate-gray)] mt-1">
                    No security issues were found for the selected filters.
                  </p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-[var(--color-hairline)] bg-[var(--color-cloud)] text-[11px] font-bold text-[var(--color-slate-gray)] select-none">
                        <th className="px-4 py-3 font-semibold">Severity</th>
                        <th className="px-4 py-3 font-semibold">Finding</th>
                        <th className="px-4 py-3 font-semibold">Rule ID</th>
                        <th className="px-4 py-3 font-semibold">Framework Control</th>
                        <th className="px-4 py-3 font-semibold">Status</th>
                        <th className="px-4 py-3 text-right font-semibold">Evidence</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[var(--color-hairline)]">
                      {findings.map((f, idx) => {
                        let sevBadge = 'bg-sky-50 text-sky-700 border-sky-200';
                        let SevIcon = AlertCircle;

                        if (f.severity === 'critical') {
                          sevBadge = 'bg-rose-50 text-rose-700 border-rose-200';
                          SevIcon = AlertTriangle;
                        } else if (f.severity === 'high') {
                          sevBadge = 'bg-orange-50 text-orange-700 border-orange-200';
                          SevIcon = ShieldAlert;
                        } else if (f.severity === 'medium') {
                          sevBadge = 'bg-amber-50 text-amber-700 border-amber-200';
                        }

                        const isExpanded = expandedFinding === f.control_id;

                        return (
                          <Fragment key={idx}>
                          <tr
                            onClick={() => setExpandedFinding(isExpanded ? null : f.control_id)}
                            className="cursor-pointer transition-colors hover:bg-[var(--color-pebble)] group"
                          >
                            <td className="px-4 py-3.5">
                              <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10.5px] font-bold border ${sevBadge}`}>
                                <SevIcon className="w-3 h-3" />
                                {f.severity.charAt(0).toUpperCase() + f.severity.slice(1)}
                              </span>
                            </td>
                            <td className="px-4 py-3.5 font-bold text-[var(--color-ink-navy)] group-hover:text-[var(--color-signal-blue)] transition-colors">
                              {f.title}
                              {frameworkFilter !== 'all' && !citesSelected(f) && (
                                <span className="ml-2 align-middle px-2 py-0.5 rounded-full bg-rose-50 border border-rose-200 text-[10px] font-bold text-rose-700">
                                  Urgent · outside this framework
                                </span>
                              )}
                            </td>
                            <td className="px-4 py-3.5 font-mono text-[11px] text-[var(--color-slate-gray)]">
                              {f.control_id}
                            </td>
                            <td className="px-4 py-3.5 font-mono text-[11px] text-[var(--color-slate-gray)]">
                              {(frameworkFilter !== 'all'
                                ? f.frameworks?.[frameworkFilter]?.join(', ')
                                : f.frameworks?.nist_800_53?.[0] ||
                                  f.frameworks?.cis_ids?.[0]) || 'Unmapped'}
                            </td>
                            <td className="px-4 py-3.5">
                              <span className={`inline-flex px-2 py-0.5 rounded-full text-[10.5px] font-semibold border ${
                                f.state === 'FAIL' ? 'bg-rose-50 text-rose-700 border-rose-200' :
                                f.state === 'PASS' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' :
                                'bg-slate-50 text-slate-700 border-slate-200'
                              }`}>
                                {f.state}
                              </span>
                            </td>
                            <td className="px-4 py-3.5 text-right">
                              <ChevronRight className={`inline w-4 h-4 text-[var(--color-mist-gray)] transition-transform ${isExpanded ? 'rotate-90 text-[var(--color-ink-navy)]' : 'group-hover:text-[var(--color-ink-navy)]'}`} />
                            </td>
                          </tr>
                          {/* The detail gets the full table width. Inside the
                              title cell it was ~280px wide, which broke field
                              names mid-word and squeezed the evidence lines --
                              the one thing here that has to be read exactly. */}
                          {isExpanded && (
                            <tr className="bg-[var(--color-cloud)]">
                              <td colSpan={6} className="px-4 py-4">
                                <div className="space-y-3 text-xs font-normal text-[var(--color-slate-gray)] leading-relaxed">
                                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                                    <div>
                                      <span className="block text-[10px] uppercase tracking-wider font-bold">Setting checked</span>
                                      <code className="font-mono text-[11px] text-[var(--color-ink-navy)] break-all">{f.field}</code>
                                    </div>
                                    <div>
                                      <span className="block text-[10px] uppercase tracking-wider font-bold">Required</span>
                                      <code className="font-mono text-[11px] text-[var(--color-ink-navy)] break-all">{show(f.expected)}</code>
                                    </div>
                                    <div>
                                      <span className="block text-[10px] uppercase tracking-wider font-bold">Found</span>
                                      <code className="font-mono text-[11px] text-[var(--color-ink-navy)] break-all">{show(f.observed)}</code>
                                    </div>
                                  </div>

                                  <div>
                                    <span className="block text-[10px] uppercase tracking-wider font-bold mb-0.5">Why this fired</span>
                                    <p className="text-[var(--color-ink-navy)]">{f.reason}</p>
                                  </div>

                                  {f.evidence?.length > 0 ? (
                                    <div>
                                      <span className="block text-[10px] uppercase tracking-wider font-bold mb-1">
                                        Evidence from the configuration ({f.evidence.length})
                                      </span>
                                      <div className="space-y-1">
                                        {f.evidence.map((e, i) => (
                                          <div key={i} className="p-2 rounded bg-[var(--color-pebble)] font-mono text-[11px] text-[var(--color-ink-navy)]">
                                            <div className="text-[10px] text-[var(--color-slate-gray)] mb-1 flex items-center gap-1">
                                              <Terminal className="w-3 h-3" />
                                              {e.file}
                                              {e.line !== null
                                                ? ` · line ${e.line}`
                                                : e.record_id
                                                  ? ` · ${e.record_id}`
                                                  : ''}
                                            </div>
                                            <code className="break-all">{e.raw}</code>
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  ) : (
                                    <p className="italic">
                                      No line in the configuration states this setting. The absence is the finding.
                                    </p>
                                  )}

                                  <div>
                                    <span className="block text-[10px] uppercase tracking-wider font-bold mb-1">Cited by</span>
                                    <div className="flex flex-wrap gap-1">
                                      {CITATIONS.map(({ key, label }) => {
                                        const ids = f.frameworks?.[key] ?? [];
                                        if (!ids.length) return null;
                                        return (
                                          <span
                                            key={key}
                                            className="px-2 py-0.5 rounded-full bg-[var(--color-cloud)] border border-[var(--color-hairline)] text-[10.5px] font-semibold text-[var(--color-ink-navy)]"
                                          >
                                            {label}: {ids.join(', ')}
                                          </span>
                                        );
                                      })}
                                      {!CITATIONS.some(({ key }) => (f.frameworks?.[key] ?? []).length) && (
                                        <span className="text-[11px]">
                                          Not cited by any framework in this run.
                                        </span>
                                      )}
                                    </div>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                          </Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          )}

          {activeTab === 'compliance' && (
            <Card className="p-6 bg-white border border-[var(--color-hairline)]">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-bold text-[var(--color-ink-navy)]">
                  Compliance Summary
                </h3>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs text-center">
                <div className="p-4 border border-[var(--color-hairline)] rounded-xl bg-emerald-50/50">
                   <div className="text-2xl font-bold text-emerald-600 mb-1">{data.counts.PASS || 0}</div>
                   <div className="font-semibold text-emerald-800 uppercase tracking-wide text-[10px]">Pass</div>
                </div>
                <div className="p-4 border border-[var(--color-hairline)] rounded-xl bg-rose-50/50">
                   <div className="text-2xl font-bold text-rose-600 mb-1">{data.counts.FAIL || 0}</div>
                   <div className="font-semibold text-rose-800 uppercase tracking-wide text-[10px]">Fail</div>
                </div>
                <div className="p-4 border border-[var(--color-hairline)] rounded-xl bg-amber-50/50">
                   <div className="text-2xl font-bold text-amber-600 mb-1">{data.counts.PARTIAL || 0}</div>
                   <div className="font-semibold text-amber-800 uppercase tracking-wide text-[10px]">Partial</div>
                </div>
                <div className="p-4 border border-[var(--color-hairline)] rounded-xl bg-slate-50/50">
                   <div className="text-2xl font-bold text-slate-600 mb-1">{(data.counts.UNKNOWN || 0) + (data.counts.NOT_APPLICABLE || 0)}</div>
                   <div className="font-semibold text-slate-800 uppercase tracking-wide text-[10px]">Other</div>
                </div>
              </div>
            </Card>
          )}

          {activeTab === 'analysis' && (
            <AnalysisTabs assessmentId={id!} />
          )}

        </div>

        {/* RIGHT COLUMN (Cols 4) */}
        <div className="lg:col-span-4 space-y-6">
          <Card className="p-6 bg-white border border-[var(--color-hairline)]">
            <h3 className="text-sm font-bold text-[var(--color-ink-navy)] mb-4">
              Metadata
            </h3>
            <div className="space-y-3 text-xs">
              <div className="flex items-center justify-between py-1 border-b border-[var(--color-hairline)]">
                <span className="text-[var(--color-slate-gray)]">Assessment ID</span>
                <span className="font-bold text-[var(--color-ink-navy)]">{assessmentDisplayId}</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-[var(--color-hairline)]">
                <span className="text-[var(--color-slate-gray)]">Device Name</span>
                <span className="font-bold text-[var(--color-ink-navy)]">{deviceName}</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-[var(--color-hairline)]">
                <span className="text-[var(--color-slate-gray)]">Vendor / Platform</span>
                <span className="font-medium text-[var(--color-ink-navy)]">{vendorClean} · {platformClean}</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-[var(--color-hairline)]">
                <span className="text-[var(--color-slate-gray)]">Source File</span>
                <span className="font-medium text-[var(--color-ink-navy)] truncate max-w-[150px]">{identity.source_file}</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-[var(--color-hairline)]">
                <span className="text-[var(--color-slate-gray)]">Status</span>
                <span className="px-2 py-0.5 text-[10px] font-semibold rounded-full bg-blue-50 text-blue-700 border border-blue-200">
                  Completed
                </span>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default AssessmentDetail;
