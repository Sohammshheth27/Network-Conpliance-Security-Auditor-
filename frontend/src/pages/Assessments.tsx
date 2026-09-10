import { useMemo, useState, type FC } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Plus,
  Search,
  ArrowRight,
  Server,
  ShieldCheck,
  Gauge,
  RefreshCw,
} from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Empty, ErrorPanel, Loading } from '../components/ui/States';
import { api, vendorLabel, type AssessmentSummary } from '../lib/api';
import { useApi } from '../lib/useApi';

/**
 * Colour the score by band, but never above coverage.
 *
 * A 100% score on 30% coverage is not a green result, so the band is capped by
 * how much of the device we could actually read.
 */
function scoreTone(score: number, assessed: number): string {
  const effective = Math.min(score, assessed);
  if (effective >= 80) return 'text-[#32D6A8]';
  if (effective >= 50) return 'text-[#F5B82E]';
  return 'text-[#E5484D]';
}

const Assessments: FC = () => {
  const navigate = useNavigate();
  const [searchTerm, setSearchTerm] = useState('');
  const [vendorFilter, setVendorFilter] = useState('All');

  const { data, loading, error, reload } = useApi<AssessmentSummary[]>(
    () => api.assessments(),
    [],
  );

  // Memoise on `data`, not on a `data ?? []` fallback: the fallback is a new
  // array identity every render, so the memo would never actually memoise.
  const rows = useMemo(() => data ?? [], [data]);

  const vendors = useMemo(
    () => ['All', ...new Set(rows.map((r) => r.vendor))],
    [rows],
  );

  const filtered = rows.filter((item) => {
    const q = searchTerm.toLowerCase();
    const matchesSearch =
      !q ||
      item.device.toLowerCase().includes(q) ||
      item.vendor.toLowerCase().includes(q) ||
      item.assessment_id.toLowerCase().includes(q);
    const matchesVendor = vendorFilter === 'All' || item.vendor === vendorFilter;
    return matchesSearch && matchesVendor;
  });

  const meanScore = rows.length
    ? Math.round(rows.reduce((a, r) => a + r.score_pct, 0) / rows.length)
    : 0;
  const meanCoverage = rows.length
    ? Math.round(rows.reduce((a, r) => a + r.assessed_pct, 0) / rows.length)
    : 0;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <span className="text-[11px] font-bold uppercase tracking-widest text-[#2D8CFF] block mb-1">
            NCSA ASSESSMENTS
          </span>
          <h1 className="text-3xl font-semibold tracking-tight text-[#F5F8FF]">
            Assessments
          </h1>
          <p className="text-sm text-[#AAB8D0] mt-1">
            Every configuration assessed in this engine session.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={reload}
            className="rounded-full border border-[rgba(100,150,220,0.22)] p-2.5 text-[#AAB8D0] transition-colors hover:text-[#F5F8FF]"
            aria-label="Reload"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <Button
            variant="primary"
            className="flex items-center gap-2 text-sm font-semibold py-2.5 px-5 rounded-full"
            onClick={() => navigate('/new-audit')}
          >
            <Plus className="w-4 h-4" />
            <span>New Audit</span>
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card variant="panel" className="flex items-center gap-4">
          <div className="w-10 h-10 rounded-xl bg-[rgba(22,119,255,0.15)] text-[#2D8CFF] flex items-center justify-center">
            <Server className="w-5 h-5" />
          </div>
          <div>
            <span className="text-xs text-[#AAB8D0] font-medium block">
              Devices assessed
            </span>
            <span className="text-xl font-bold text-[#F5F8FF]">{rows.length}</span>
          </div>
        </Card>

        <Card variant="panel" className="flex items-center gap-4">
          <div className="w-10 h-10 rounded-xl bg-[rgba(50,214,168,0.15)] text-[#32D6A8] flex items-center justify-center">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <span className="text-xs text-[#AAB8D0] font-medium block">
              Mean score
            </span>
            <span className="text-xl font-bold text-[#F5F8FF]">{meanScore}%</span>
          </div>
        </Card>

        {/* Coverage is a first-class KPI, not a footnote. A score without it
            is unreadable: 100% of what we could check is not 100% of the
            device. */}
        <Card variant="panel" className="flex items-center gap-4">
          <div className="w-10 h-10 rounded-xl bg-[rgba(245,184,46,0.15)] text-[#F5B82E] flex items-center justify-center">
            <Gauge className="w-5 h-5" />
          </div>
          <div>
            <span className="text-xs text-[#AAB8D0] font-medium block">
              Mean coverage
            </span>
            <span className="text-xl font-bold text-[#F5F8FF]">
              {meanCoverage}%
            </span>
          </div>
        </Card>
      </div>

      <Card variant="default" className="p-0 overflow-hidden">
        <div className="p-5 border-b border-[rgba(100,150,220,0.12)] flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#65738B]" />
            <input
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by device, vendor or assessment id..."
              className="w-full rounded-full bg-[rgba(11,21,40,0.6)] border border-[rgba(100,150,220,0.16)] pl-9 pr-4 py-2 text-sm text-[#F5F8FF] placeholder:text-[#65738B] outline-none focus:border-[#1677FF]"
            />
          </div>
          <select
            value={vendorFilter}
            onChange={(e) => setVendorFilter(e.target.value)}
            className="rounded-full bg-[rgba(11,21,40,0.6)] border border-[rgba(100,150,220,0.16)] px-4 py-2 text-sm text-[#F5F8FF] outline-none focus:border-[#1677FF]"
          >
            {vendors.map((v) => (
              <option key={v} value={v}>
                {v === 'All' ? 'All vendors' : vendorLabel(v)}
              </option>
            ))}
          </select>
        </div>

        {loading && <Loading label="Reading assessments" />}
        {error && (
          <div className="p-5">
            <ErrorPanel error={error} onRetry={reload} />
          </div>
        )}

        {!loading && !error && filtered.length === 0 && (
          <Empty
            label={
              rows.length === 0
                ? 'Nothing assessed yet. Upload a configuration to begin.'
                : 'No assessment matches those filters.'
            }
          />
        )}

        {!loading && !error && filtered.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-[11px] uppercase tracking-wider text-[#65738B] border-b border-[rgba(100,150,220,0.12)]">
                  <th className="px-5 py-3 font-semibold">Device</th>
                  <th className="px-5 py-3 font-semibold">Vendor</th>
                  <th className="px-5 py-3 font-semibold">Score</th>
                  <th className="px-5 py-3 font-semibold">Coverage</th>
                  <th className="px-5 py-3 font-semibold">Assessment</th>
                  <th className="px-5 py-3" />
                </tr>
              </thead>
              <tbody>
                {filtered.map((item) => (
                  <tr
                    key={item.assessment_id}
                    onClick={() => navigate(`/assessments/${item.assessment_id}`)}
                    className="border-b border-[rgba(100,150,220,0.08)] last:border-0 cursor-pointer transition-colors hover:bg-[rgba(22,119,255,0.06)]"
                  >
                    <td className="px-5 py-3.5 font-mono text-[#F5F8FF]">
                      {item.device}
                    </td>
                    <td className="px-5 py-3.5">
                      <Badge variant="info">{vendorLabel(item.vendor)}</Badge>
                    </td>
                    <td
                      className={`px-5 py-3.5 font-bold ${scoreTone(
                        item.score_pct,
                        item.assessed_pct,
                      )}`}
                    >
                      {item.score_pct}%
                    </td>
                    {/* Coverage sits in its own column, always. It is not a
                        tooltip on the score -- it qualifies the score, and a
                        reader must not be able to see one without the other. */}
                    <td className="px-5 py-3.5 text-[#AAB8D0]">
                      {item.assessed_pct}%
                    </td>
                    <td className="px-5 py-3.5 font-mono text-[11px] text-[#65738B]">
                      {item.assessment_id}
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      <ArrowRight className="inline w-4 h-4 text-[#65738B]" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <p className="text-[11.5px] text-[#65738B] px-1">
        Score is computed over decided controls only and is always shown beside
        coverage. A high score on low coverage means we could read little of the
        device, not that the device is well configured.
      </p>
    </div>
  );
};

export default Assessments;
