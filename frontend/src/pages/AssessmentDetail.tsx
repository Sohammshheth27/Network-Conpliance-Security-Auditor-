import { useMemo, useState, type FC } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, Search, Server, Terminal } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { RadialProgress } from '../components/ui/RadialProgress';
import {
  Empty,
  ErrorPanel,
  Loading,
  SeverityPill,
  StatePill,
} from '../components/ui/States';
import {
  api,
  coverageCaption,
  failuresBySeverity,
  RESULT_STATES,
  STATE_MEANING,
  STATE_STYLE,
  vendorLabel,
  type Assessment,
  type Finding,
  type ResultState,
  type Severity,
} from '../lib/api';
import { useApi } from '../lib/useApi';
import { AnalysisTabs } from '../components/analysis/AnalysisTabs';

type Tab = 'findings' | 'analysis' | 'records' | 'remediation';

const TABS: { id: Tab; label: string }[] = [
  { id: 'findings', label: 'Findings' },
  { id: 'analysis', label: 'Deeper analysis' },
  { id: 'remediation', label: 'Remediation' },
  { id: 'records', label: 'Parse accounting' },
];

/** One finding row, expanding to its evidence. */
const FindingRow: FC<{ finding: Finding }> = ({ finding }) => {
  const [open, setOpen] = useState(false);
  const fw = finding.frameworks;
  const chips = [
    ...fw.nist_800_53.map((c) => ({ label: c, src: 'NIST 800-53' })),
    ...fw.stig_ids.map((c) => ({ label: c, src: 'STIG' })),
    ...fw.cis_ids.map((c) => ({ label: c, src: 'CIS' })),
    ...fw.iso_27001.map((c) => ({ label: c, src: 'ISO 27001' })),
    // ATT&CK names the adversary technique this control stands in front of.
    // It is presentation only: no state or score is derived from it.
    ...(finding.attack ?? []).map((t) => ({
      label: `${t.id} ${t.name}`,
      src: 'MITRE ATT&CK',
    })),
  ];

  return (
    <div className="border-b border-[rgba(100,150,220,0.08)] last:border-0">
      <button
        onClick={() => setOpen(!open)}
        className="w-full px-5 py-3.5 text-left transition-colors hover:bg-[rgba(22,119,255,0.05)]"
      >
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <StatePill state={finding.state} />
              <SeverityPill severity={finding.severity} />
              <span className="font-mono text-[11px] text-[#65738B]">
                {finding.control_id}
              </span>
            </div>
            <h4 className="mt-1.5 text-sm font-semibold text-[#F5F8FF]">
              {finding.title}
            </h4>
            <p className="mt-0.5 font-mono text-[11.5px] text-[#8FA0BC]">
              {finding.field}
            </p>
          </div>
          <span className="shrink-0 text-[11px] text-[#65738B]">
            {open ? 'Hide' : 'Evidence'}
          </span>
        </div>
      </button>

      {open && (
        <div className="bg-[rgba(8,16,32,0.5)] px-5 pb-5 pt-1">
          <p className="text-[13px] leading-relaxed text-[#AAB8D0]">
            {finding.reason}
          </p>

          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <div className="rounded-xl border border-[rgba(100,150,220,0.14)] p-3">
              <span className="text-[10.5px] uppercase tracking-wider text-[#65738B]">
                Observed
              </span>
              <p className="mt-1 font-mono text-[12.5px] break-words text-[#F5F8FF]">
                {finding.observed === null || finding.observed === undefined
                  ? '— nothing observed'
                  : JSON.stringify(finding.observed)}
              </p>
            </div>
            <div className="rounded-xl border border-[rgba(100,150,220,0.14)] p-3">
              <span className="text-[10.5px] uppercase tracking-wider text-[#65738B]">
                Expected
              </span>
              <p className="mt-1 font-mono text-[12.5px] break-words text-[#F5F8FF]">
                {finding.expected === null || finding.expected === undefined
                  ? '—'
                  : JSON.stringify(finding.expected)}
              </p>
            </div>
          </div>

          {/* The single most persuasive thing in the product: the exact line of
              the exact file behind the claim. One click, never two. */}
          {finding.evidence.length > 0 && (
            <div className="mt-3">
              <span className="text-[10.5px] uppercase tracking-wider text-[#65738B]">
                Evidence — {finding.evidence.length} line
                {finding.evidence.length > 1 ? 's' : ''} from the configuration
              </span>
              <div className="mt-1.5 space-y-1.5">
                {finding.evidence.slice(0, 8).map((e, i) => {
                  // A GUTTER, the way an editor shows it -- the number sits
                  // beside the line it belongs to, not in small print above.
                  //
                  // Every reference is locatable. Where the reader supplies a
                  // line number that is the number; where the configuration is
                  // a single physical line of key=value settings, line 1 is
                  // genuinely where the value is and the setting's position
                  // along that line is what finds it.
                  const ordinal = e.record_id?.startsWith('setting[')
                    ? e.record_id.slice(8, -1)
                    : null;
                  // For a single-line export the gutter shows the SETTING
                  // number, not the line. The decoded SonicOS backup is 2.7
                  // million characters with zero newlines, so every setting is
                  // on line 1 -- true, and useless: the gutter would read 1
                  // for all 92,636 of them. The ordinal is unique and
                  // reachable with `tr '&' '\n' | sed -n 'Np'`.
                  const lineNo =
                    e.line !== null ? String(e.line) : (ordinal ?? '—');
                  const detail =
                    e.line !== null ? null : ordinal ? 'setting' : e.record_id;

                  return (
                    <div
                      key={i}
                      className="overflow-hidden rounded-lg border border-[rgba(100,150,220,0.16)] bg-[rgba(5,11,24,0.8)]"
                    >
                      <div className="flex items-stretch">
                        <div className="flex w-14 shrink-0 items-center justify-end border-r border-[rgba(100,150,220,0.16)] bg-[rgba(100,150,220,0.06)] px-2 py-2">
                          <span
                            className="font-mono text-[12px] font-semibold text-[#8FA0BC]"
                            title={
                              e.line !== null
                                ? `line ${e.line} of ${e.file}`
                                : ordinal
                                  ? `setting ${ordinal}. This export is one physical ` +
                                    `line, so a line number would read 1 for every ` +
                                    `setting. Read it with: tr '&' '\\n' < file | ` +
                                    `sed -n '${ordinal}p'`
                                  : `${e.file} — no line reference available`
                            }
                          >
                            {lineNo}
                          </span>
                        </div>
                        <pre className="min-w-0 flex-1 overflow-x-auto whitespace-pre-wrap px-3 py-2 font-mono text-[12px] text-[#DDE7F7]">
                          {e.raw}
                        </pre>
                      </div>
                      <div className="flex flex-wrap items-center gap-2 border-t border-[rgba(100,150,220,0.12)] px-3 py-1 text-[10.5px] text-[#65738B]">
                        <Terminal className="h-3 w-3" />
                        <span className="font-mono">{e.file}</span>
                        <span>
                          {e.line !== null
                            ? `line ${e.line}`
                            : ordinal
                              ? `setting ${ordinal} — one-line export, so every value is on line 1`
                              : 'no line reference'}
                        </span>
                        {detail && e.line === null && !ordinal && (
                          <span>· {detail}</span>
                        )}
                      </div>
                    </div>
                  );
                })}
                {finding.evidence.length > 8 && (
                  <p className="text-[11px] text-[#65738B]">
                    + {finding.evidence.length - 8} more evidence lines
                  </p>
                )}
              </div>
            </div>
          )}

          {chips.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {chips.slice(0, 12).map((c, i) => (
                <span
                  key={i}
                  title={c.src}
                  className="rounded-full border border-[rgba(100,150,220,0.2)] px-2 py-0.5 font-mono text-[10.5px] text-[#AAB8D0]"
                >
                  {c.label}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

const AssessmentDetail: FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>('findings');
  const [stateFilter, setStateFilter] = useState<ResultState | 'ALL'>('ALL');
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all');
  const [q, setQ] = useState('');

  const { data, loading, error, reload } = useApi<Assessment>(
    () => api.assessment(id!),
    [id],
    { enabled: Boolean(id) },
  );

  const findings = useMemo(() => {
    if (!data) return [];
    return data.findings.filter((f) => {
      if (stateFilter !== 'ALL' && f.state !== stateFilter) return false;
      if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
      if (q) {
        const s = q.toLowerCase();
        if (
          !f.title.toLowerCase().includes(s) &&
          !f.control_id.toLowerCase().includes(s) &&
          !f.field.toLowerCase().includes(s)
        )
          return false;
      }
      return true;
    });
  }, [data, stateFilter, severityFilter, q]);

  if (loading) return <Loading label="Loading assessment" />;
  if (error) return <ErrorPanel error={error} onRetry={reload} />;
  if (!data) return <Empty label="No such assessment." />;

  const { identity, coverage, counts, records } = data;
  const bySeverity = failuresBySeverity(data.findings);

  // No mapping pack for this device: nothing was decided, so there is no
  // score to show. Rendering the gauges anyway printed a blank score beside
  // "null% of 0 decided" -- a number-shaped statement about nothing.
  if (!data.supported) {
    return (
      <div className="space-y-6">
        <button
          onClick={() => navigate('/assessments')}
          className="flex items-center gap-2 text-xs font-medium text-[#AAB8D0] transition-colors hover:text-[#F5F8FF]"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Back to assessments
        </button>
        <Card variant="default" className="p-6">
          <div className="flex items-start gap-4">
            <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl border border-[rgba(100,150,220,0.2)] bg-[rgba(16,33,59,0.9)] text-[#2D8CFF]">
              <Server className="h-7 w-7" />
            </div>
            <div className="min-w-0">
              <span className="mb-1 block text-[11px] font-bold uppercase tracking-widest text-[#F5A623]">
                Not yet assessable
              </span>
              <h1 className="text-2xl font-bold tracking-tight text-[#F5F8FF]">
                {identity.hostname || identity.source_file}
              </h1>
              <p className="mt-1 text-[12px] text-[#AAB8D0]">
                Recognised as {vendorLabel(identity.vendor)}
                {identity.platform ? ` (${identity.platform})` : ''}. No mapping pack
                exists for it, so no control was evaluated and no compliance score is
                shown — a score over zero decided controls would be invented.
              </p>
            </div>
          </div>
          {data.notes?.length > 0 && (
            <ul className="mt-5 space-y-1.5 border-t border-[rgba(100,150,220,0.12)] pt-4 text-[12.5px] text-[#AAB8D0]">
              {data.notes.map((n, i) => (
                <li key={i}>• {n}</li>
              ))}
            </ul>
          )}
          <div className="mt-5">
            <button
              onClick={() => navigate('/training')}
              className="ncsa-btn-primary rounded-full px-5 py-2.5 text-xs font-semibold"
            >
              Teach this device in the Training page
            </button>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <button
        onClick={() => navigate('/assessments')}
        className="flex items-center gap-2 text-xs font-medium text-[#AAB8D0] transition-colors hover:text-[#F5F8FF]"
      >
        <ArrowLeft className="h-3.5 w-3.5" />
        Back to assessments
      </button>

      {/* ---------------------------------------------------- result header */}
      <Card variant="default" className="p-6">
        <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-start gap-4">
            <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl border border-[rgba(100,150,220,0.2)] bg-[rgba(16,33,59,0.9)] text-[#2D8CFF]">
              <Server className="h-7 w-7" />
            </div>
            <div className="min-w-0">
              <span className="mb-1 block text-[11px] font-bold uppercase tracking-widest text-[#2D8CFF]">
                {vendorLabel(identity.vendor)} · {identity.os}
              </span>
              <h1 className="text-2xl font-bold tracking-tight text-[#F5F8FF]">
                {identity.hostname || identity.source_file}
              </h1>
              <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-[#AAB8D0]">
                {identity.model && <span>{identity.model}</span>}
                {identity.version && <span>· {identity.version}</span>}
                {identity.serial && (
                  <span className="font-mono">· S/N {identity.serial}</span>
                )}
              </div>
            </div>
          </div>

          {/* Score and coverage together, never the score alone. */}
          <div className="flex items-center gap-6">
            {/* Labelled individually: the component defaults both gauges to
                "COMPLIANCE SCORE", which would caption the coverage number
                with the wrong name. */}
            <div className="text-center">
              <RadialProgress
                value={coverage.score_pct}
                size={92}
                label="COMPLIANCE"
                sublabel="SCORE"
              />
            </div>
            <div className="text-center">
              <RadialProgress
                value={coverage.assessed_pct}
                size={92}
                label="DEVICE"
                sublabel="COVERAGE"
              />
            </div>
          </div>
        </div>

        <p className="mt-5 border-t border-[rgba(100,150,220,0.12)] pt-4 text-[13px] text-[#AAB8D0]">
          {coverageCaption(coverage)} — {coverage.controls_undecided} control
          {coverage.controls_undecided === 1 ? '' : 's'} could not be decided,
          and {coverage.not_applicable} do not apply to this platform.
        </p>

        {/* Result per framework. A framework citing no control on this
            platform shows no score rather than disappearing. */}
        {data.framework_coverage?.length > 0 && (
          <div className="mt-4 overflow-x-auto">
            <div className="mb-2 text-[11px] uppercase tracking-wider text-[#65738B]">
              {data.frameworks?.length
                ? `Assessed against ${data.framework_coverage
                    .filter((f) => data.frameworks?.includes(f.framework))
                    .map((f) => f.name)
                    .join(', ')}`
                : 'Assessed against every framework'}
            </div>
            <table className="w-full text-left text-[12.5px]">
              <thead className="text-[10.5px] uppercase tracking-wider text-[#65738B]">
                <tr>
                  <th className="py-1 pr-4">Framework</th>
                  <th className="py-1 pr-4 text-right">Framework score</th>
                  <th className="py-1 pr-4 text-right">Requirements met</th>
                  <th className="py-1 pr-4 text-right">Not met</th>
                  <th className="py-1 pr-4 text-right">Undecided</th>
                  <th className="py-1 text-right">Checks passed</th>
                </tr>
              </thead>
              <tbody className="text-[#DDE7F7]">
                {data.framework_coverage.map((f) => (
                  <tr key={f.framework} className="border-t border-[rgba(100,150,220,0.1)]">
                    <td className="py-1.5 pr-4">{f.name}</td>
                    <td className="py-1.5 pr-4 text-right font-semibold">
                      {f.requirement_score_pct === null ? '—' : `${f.requirement_score_pct}%`}
                    </td>
                    <td className="py-1.5 pr-4 text-right">
                      {f.requirements_met} / {f.requirements_decided}
                    </td>
                    <td
                      className="py-1.5 pr-4 text-right text-[#E5484D]"
                      title={f.not_met_ids.join(', ')}
                    >
                      {f.requirements_not_met}
                    </td>
                    <td className="py-1.5 pr-4 text-right text-[#8FA0BC]">
                      {f.requirements - f.requirements_decided}
                    </td>
                    <td className="py-1.5 text-right text-[#8FA0BC]">
                      {f.passed} / {f.decided}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="mt-2 text-[11.5px] leading-relaxed text-[#8FA0BC]">
              Each framework is scored over its own requirements — NIST controls,
              ISO/IEC 27001 Annex A controls, STIG IDs. A requirement is met only
              when every check citing it passes; one failing check fails every
              requirement that cites it, and an undecided check leaves it
              undecided. Hover a “Not met” count for the requirement IDs.
            </p>
          </div>
        )}

        {/* All seven states. Collapsing to pass/fail would be a tidier chart
            and a dishonest one. */}
        <div className="mt-4 flex flex-wrap gap-2">
          {RESULT_STATES.map((s) => (
            <div
              key={s}
              title={STATE_MEANING[s]}
              className={`rounded-xl border px-3 py-2 ${STATE_STYLE[s]}`}
            >
              <span className="block text-lg font-bold leading-none">
                {counts[s] ?? 0}
              </span>
              <span className="text-[10px] font-semibold uppercase tracking-wide">
                {s.replace('_', ' ')}
              </span>
            </div>
          ))}
        </div>
      </Card>

      {/* ------------------------------------------------------------ tabs */}
      <div className="flex gap-1 overflow-x-auto border-b border-[rgba(100,150,220,0.12)]">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`whitespace-nowrap px-4 py-2.5 text-sm font-semibold transition-colors ${
              tab === t.id
                ? 'border-b-2 border-[#1677FF] text-[#F5F8FF]'
                : 'text-[#8FA0BC] hover:text-[#F5F8FF]'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'findings' && (
        <Card variant="default" className="overflow-hidden p-0">
          <div className="flex flex-col gap-3 border-b border-[rgba(100,150,220,0.12)] p-5 sm:flex-row">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#65738B]" />
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Search controls, titles or fields..."
                className="w-full rounded-full border border-[rgba(100,150,220,0.16)] bg-[rgba(11,21,40,0.6)] py-2 pl-9 pr-4 text-sm text-[#F5F8FF] outline-none placeholder:text-[#65738B] focus:border-[#1677FF]"
              />
            </div>
            <select
              value={stateFilter}
              onChange={(e) => setStateFilter(e.target.value as ResultState | 'ALL')}
              className="rounded-full border border-[rgba(100,150,220,0.16)] bg-[rgba(11,21,40,0.6)] px-4 py-2 text-sm text-[#F5F8FF] outline-none focus:border-[#1677FF]"
            >
              <option value="ALL">All states</option>
              {RESULT_STATES.map((s) => (
                <option key={s} value={s}>
                  {s.replace('_', ' ')} ({counts[s] ?? 0})
                </option>
              ))}
            </select>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value as Severity | 'all')}
              className="rounded-full border border-[rgba(100,150,220,0.16)] bg-[rgba(11,21,40,0.6)] px-4 py-2 text-sm text-[#F5F8FF] outline-none focus:border-[#1677FF]"
            >
              <option value="all">All severities</option>
              {(['critical', 'high', 'medium', 'low'] as Severity[]).map((s) => (
                <option key={s} value={s}>
                  {s} ({bySeverity[s]} failing)
                </option>
              ))}
            </select>
          </div>

          {findings.length === 0 ? (
            <Empty label="No finding matches those filters." />
          ) : (
            <div>
              {findings.map((f) => (
                <FindingRow key={f.control_id} finding={f} />
              ))}
            </div>
          )}
        </Card>
      )}

      {tab === 'analysis' && <AnalysisTabs assessmentId={data.assessment_id} />}

      {tab === 'remediation' && <RemediationPanel assessmentId={data.assessment_id} />}

      {tab === 'records' && (
        <Card variant="default" className="p-6">
          <h3 className="mb-1 text-sm font-bold uppercase tracking-wider text-[#F5F8FF]">
            Parse accounting
          </h3>
          <p className="mb-4 text-[12.5px] text-[#8FA0BC]">
            What we read from the file, and what we could not map. These numbers
            are why the coverage figure is what it is.
          </p>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            {[
              ['Source records', records.source_records],
              ['Parsed', records.parsed_records],
              ['Unreadable', records.unreadable_records],
              ['Mapped to schema', records.mapped_to_schema],
              ['Parsed, not mapped', records.parsed_not_mapped],
              ['Security-relevant unmapped', records.security_relevant_unmapped],
            ].map(([label, value]) => (
              <div
                key={label as string}
                className="rounded-xl border border-[rgba(100,150,220,0.14)] p-3"
              >
                <span className="block text-lg font-bold text-[#F5F8FF]">
                  {(value as number).toLocaleString()}
                </span>
                <span className="text-[11px] text-[#8FA0BC]">{label}</span>
              </div>
            ))}
          </div>
          <div className="mt-4 flex flex-wrap gap-3 border-t border-[rgba(100,150,220,0.12)] pt-4 text-[12px] text-[#AAB8D0]">
            <span>
              Objects: <strong className="text-[#F5F8FF]">{data.objects}</strong>
            </span>
            <span>
              Relationships:{' '}
              <strong className="text-[#F5F8FF]">{data.relationships}</strong>
            </span>
            <span>
              Risk total:{' '}
              <strong className="text-[#F5F8FF]">{data.risk_total}</strong>
            </span>
            <Badge variant="warning">Worst: {data.risk_worst}</Badge>
          </div>
        </Card>
      )}
    </div>
  );
};

/** Remediation, with the unavailable list shown rather than hidden. */
const RemediationPanel: FC<{ assessmentId: string }> = ({ assessmentId }) => {
  const { data, loading, error, reload } = useApi(
    () => api.remediation(assessmentId),
    [assessmentId],
  );

  if (loading) return <Loading label="Building remediation" />;
  if (error) return <ErrorPanel error={error} onRetry={reload} />;
  if (!data) return null;

  return (
    <div className="space-y-4">
      <Card variant="default" className="p-6">
        <h3 className="mb-1 text-sm font-bold uppercase tracking-wider text-[#F5F8FF]">
          Remediation script
        </h3>
        <p className="mb-4 text-[12.5px] text-[#8FA0BC]">
          Platform: {data.platform}. Review before running — these are
          suggestions derived from findings, not a change ticket.
        </p>
        {data.script ? (
          <pre className="overflow-x-auto rounded-xl border border-[rgba(100,150,220,0.16)] bg-[rgba(5,11,24,0.8)] p-4 text-[12px] leading-relaxed text-[#DDE7F7]">
            {data.script}
          </pre>
        ) : (
          <Empty label="No remediation commands were generated." />
        )}
        {data.rollback_command && (
          <div className="mt-3 rounded-xl border border-[rgba(245,184,46,0.28)] bg-[rgba(245,184,46,0.07)] p-3">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[#F5B82E]">
              Rollback
            </span>
            <pre className="mt-1 font-mono text-[12px] text-[#DDE7F7]">
              {data.rollback_command}
            </pre>
            {data.rollback_note && (
              <p className="mt-1 text-[11.5px] text-[#AAB8D0]">
                {data.rollback_note}
              </p>
            )}
          </div>
        )}
      </Card>

      {/* Controls we could NOT generate a fix for are listed explicitly. An
          absent fix is a gap in our remediation coverage, and hiding it would
          make the script look more complete than it is. */}
      {data.unavailable?.length > 0 && (
        <Card variant="default" className="p-6">
          <h3 className="mb-1 text-sm font-bold uppercase tracking-wider text-[#F5F8FF]">
            No remediation available — {data.unavailable.length} control
            {data.unavailable.length === 1 ? '' : 's'}
          </h3>
          <p className="mb-3 text-[12.5px] text-[#8FA0BC]">
            These failed but we hold no vendor command mapping for them yet.
            They are listed rather than dropped, so the script is not mistaken
            for a complete fix.
          </p>
          <div className="flex flex-wrap gap-1.5">
            {data.unavailable.map((c) => (
              <span
                key={c}
                className="rounded-full border border-[rgba(100,150,220,0.2)] px-2 py-0.5 font-mono text-[11px] text-[#AAB8D0]"
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

export default AssessmentDetail;
