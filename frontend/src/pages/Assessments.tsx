import { useMemo, useState, type FC } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Plus,
  Search,
  ChevronRight,
  FileText,
  CheckCircle2,
  AlertCircle,
  Clock,
  Calendar,
  ChevronDown,
} from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Empty, Loading } from '../components/ui/States';
import { api, vendorLabel, type AssessmentSummary } from '../lib/api';
import { useApi } from '../lib/useApi';

// Vendor color and brand icon helper
function VendorBrand({ vendor, platform }: { vendor: string; platform?: string }) {
  const v = vendor.toLowerCase();
  let bg = 'bg-slate-800 text-white';
  let initial = 'V';
  let label = vendorLabel(vendor);

  if (v.includes('fortinet')) {
    bg = 'bg-red-600 text-white';
    initial = 'F';
    label = 'Fortinet';
  } else if (v.includes('cisco')) {
    bg = 'bg-sky-600 text-white';
    initial = 'C';
    label = 'Cisco';
  } else if (v.includes('palo') || v.includes('panos')) {
    bg = 'bg-orange-600 text-white';
    initial = 'P';
    label = 'Palo Alto';
  } else if (v.includes('juniper')) {
    bg = 'bg-emerald-700 text-white';
    initial = 'J';
    label = 'Juniper';
  } else if (v.includes('check')) {
    bg = 'bg-pink-600 text-white';
    initial = 'CP';
    label = 'Check Point';
  } else if (v.includes('aws')) {
    bg = 'bg-amber-900 text-amber-200';
    initial = 'AWS';
    label = 'AWS';
  } else if (v.includes('sonicwall')) {
    bg = 'bg-orange-500 text-white';
    initial = 'SW';
    label = 'SonicWall';
  }

  return (
    <div className="flex items-center gap-2.5">
      <div className={`w-7 h-7 rounded-lg ${bg} flex items-center justify-center font-bold text-[10px] shadow-xs shrink-0`}>
        {initial}
      </div>
      <div className="flex flex-col">
        <span className="text-xs font-bold text-[var(--color-ink-navy)]">{label}</span>
        <span className="text-[11px] text-[var(--color-slate-gray)]">
          {platform || (v.includes('fortinet') ? 'FortiOS' : v.includes('cisco') ? 'IOS-XE' : v.includes('juniper') ? 'Junos' : 'System')}
        </span>
      </div>
    </div>
  );
}

// Circular Score Ring component matching reference
function ScoreRing({ score }: { score: number }) {
  const radius = 15;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="relative w-10 h-10 flex items-center justify-center">
      <svg className="w-10 h-10 -rotate-90">
        <circle
          cx="20"
          cy="20"
          r={radius}
          stroke="var(--color-pebble)"
          strokeWidth="2.5"
          fill="none"
        />
        <circle
          cx="20"
          cy="20"
          r={radius}
          stroke="var(--color-signal-blue)"
          strokeWidth="2.5"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          fill="none"
          className="transition-all duration-500"
        />
      </svg>
      <span className="absolute text-[11px] font-bold text-[var(--color-ink-navy)]">
        {Math.round(score)}
      </span>
    </div>
  );
}

const Assessments: FC = () => {
  const navigate = useNavigate();
  const [searchTerm, setSearchTerm] = useState('');
  const [vendorFilter, setVendorFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');

  const { data, loading } = useApi<AssessmentSummary[]>(
    () => api.assessments(),
    [],
    { cacheKey: 'assessments' }
  );

  const rows = useMemo(() => data ?? [], [data]);

  const vendors = useMemo(
    () => ['All', ...new Set(rows.map((r) => r.vendor))],
    [rows],
  );

  const filtered = useMemo(() => {
    return rows.filter((item) => {
      const q = searchTerm.toLowerCase();
      const matchesSearch =
        !q ||
        item.device.toLowerCase().includes(q) ||
        item.vendor.toLowerCase().includes(q) ||
        item.assessment_id.toLowerCase().includes(q);
      const matchesVendor = vendorFilter === 'All' || item.vendor === vendorFilter;
      const isCompleted = item.score_pct >= 50;
      const matchesStatus = 
        statusFilter === 'All' ||
        (statusFilter === 'Completed' && isCompleted) ||
        (statusFilter === 'In Progress' && !isCompleted);

      return matchesSearch && matchesVendor && matchesStatus;
    });
  }, [rows, searchTerm, vendorFilter, statusFilter]);

  const totalAssessmentsCount = loading ? '...' : rows.length;
  const completedCount = loading ? '...' : rows.filter(r => r.score_pct >= 50).length;
  const inProgressCount = loading ? '...' : rows.filter(r => r.score_pct < 50 && r.score_pct > 0).length;
  const failedCount = loading ? '...' : rows.filter(r => r.score_pct === 0).length;

  return (
    <div className="space-y-6 max-w-[1440px] mx-auto">
      {/* 1. Header with Page Title and CTA */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[var(--color-ink-navy)]">
            Assessments
          </h1>
          <p className="text-xs sm:text-sm text-[var(--color-slate-gray)] mt-1 font-medium">
            View and manage all network security assessments across your infrastructure.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button
            className="flex items-center gap-2 text-xs font-semibold py-2.5 px-4 rounded-lg bg-[#0a0a0a] text-white hover:bg-[#222222] shadow-sm transition-all"
            onClick={() => navigate('/new-audit')}
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Assessment</span>
          </Button>
        </div>
      </div>

      {/* 2. Top 4 Stat Cards matching reference image */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Total Assessments */}
        <Card className="p-5 bg-white border border-[var(--color-hairline)] flex items-center justify-between">
          <div className="flex items-start gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-blue-50 text-[var(--color-signal-blue)] flex items-center justify-center shrink-0">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <span className="text-xs text-[var(--color-slate-gray)] font-medium block">
                Total Assessments
              </span>
              <span className="text-2xl font-bold text-[var(--color-ink-navy)] block mt-0.5">
                {totalAssessmentsCount}
              </span>
              <span className="text-[11px] text-[var(--color-mist-gray)] block mt-0.5">
                Across all devices
              </span>
            </div>
          </div>
        </Card>

        {/* Card 2: Completed */}
        <Card className="p-5 bg-white border border-[var(--color-hairline)] flex items-center justify-between">
          <div className="flex items-start gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center shrink-0">
              <CheckCircle2 className="w-5 h-5" />
            </div>
            <div>
              <span className="text-xs text-[var(--color-slate-gray)] font-medium block">
                Completed
              </span>
              <span className="text-2xl font-bold text-[var(--color-ink-navy)] block mt-0.5">
                {completedCount}
              </span>
            </div>
          </div>
        </Card>

        {/* Card 3: In Progress */}
        <Card className="p-5 bg-white border border-[var(--color-hairline)] flex items-center justify-between">
          <div className="flex items-start gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-sky-50 text-sky-600 flex items-center justify-center shrink-0">
              <Clock className="w-5 h-5" />
            </div>
            <div>
              <span className="text-xs text-[var(--color-slate-gray)] font-medium block">
                In Progress
              </span>
              <span className="text-2xl font-bold text-[var(--color-ink-navy)] block mt-0.5">
                {inProgressCount}
              </span>
              <span className="text-[11px] text-[var(--color-slate-gray)] block mt-0.5">
                Running rules engines
              </span>
            </div>
          </div>
        </Card>

        {/* Card 4: Failed */}
        <Card className="p-5 bg-white border border-[var(--color-hairline)] flex items-center justify-between">
          <div className="flex items-start gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-rose-50 text-rose-600 flex items-center justify-center shrink-0">
              <AlertCircle className="w-5 h-5" />
            </div>
            <div>
              <span className="text-xs text-[var(--color-slate-gray)] font-medium block">
                Failed
              </span>
              <span className="text-2xl font-bold text-[var(--color-ink-navy)] block mt-0.5">
                {failedCount}
              </span>
              <span className="text-[11px] text-rose-600 font-semibold block mt-0.5">
                ↗ +2 from last month
              </span>
            </div>
          </div>
        </Card>
      </div>

      {/* 3. Filters Bar matching reference */}
      <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
        <div className="relative flex-1 min-w-[240px] max-w-[340px]">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--color-mist-gray)]" />
          <input
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search assessments..."
            className="w-full rounded-xl bg-white border border-[var(--color-hairline)] pl-10 pr-4 py-2 text-xs text-[var(--color-ink-navy)] placeholder:text-[var(--color-mist-gray)] outline-none focus:border-[var(--color-signal-blue)] shadow-xs"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Vendor Filter */}
          <div className="relative">
            <select
              value={vendorFilter}
              onChange={(e) => setVendorFilter(e.target.value)}
              className="appearance-none rounded-xl bg-white border border-[var(--color-hairline)] pl-3.5 pr-8 py-2 text-xs font-medium text-[var(--color-ink-navy)] outline-none shadow-xs cursor-pointer hover:bg-[var(--color-pebble)] transition-colors"
            >
              {vendors.map((v) => (
                <option key={v} value={v}>
                  {v === 'All' ? 'All Vendors' : vendorLabel(v)}
                </option>
              ))}
            </select>
            <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--color-slate-gray)] pointer-events-none" />
          </div>

          {/* Status Filter */}
          <div className="relative">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="appearance-none rounded-xl bg-white border border-[var(--color-hairline)] pl-3.5 pr-8 py-2 text-xs font-medium text-[var(--color-ink-navy)] outline-none shadow-xs cursor-pointer hover:bg-[var(--color-pebble)] transition-colors"
            >
              <option value="All">All Status</option>
              <option value="Completed">Completed</option>
              <option value="In Progress">In Progress</option>
            </select>
            <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--color-slate-gray)] pointer-events-none" />
          </div>

          {/* Frameworks Filter */}
          <div className="relative">
            <select
              className="appearance-none rounded-xl bg-white border border-[var(--color-hairline)] pl-3.5 pr-8 py-2 text-xs font-medium text-[var(--color-ink-navy)] outline-none shadow-xs cursor-pointer hover:bg-[var(--color-pebble)] transition-colors"
            >
              <option>All Frameworks</option>
              <option>CIS Benchmarks</option>
              <option>NIST SP 800-53</option>
              <option>PCI-DSS v4.0</option>
            </select>
            <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--color-slate-gray)] pointer-events-none" />
          </div>

          {/* Date Filter */}
          <div className="flex items-center gap-1.5 rounded-xl bg-white border border-[var(--color-hairline)] px-3.5 py-2 text-xs font-medium text-[var(--color-ink-navy)] shadow-xs cursor-pointer hover:bg-[var(--color-pebble)] transition-colors">
            <Calendar className="w-3.5 h-3.5 text-[var(--color-slate-gray)]" />
            <span>Last 30 days</span>
            <ChevronDown className="w-3.5 h-3.5 text-[var(--color-slate-gray)] ml-1" />
          </div>
        </div>
      </div>

      {/* 4. PRIMARY OBJECT: Historical Assessment Table */}
      <Card className="p-0 overflow-hidden bg-white border border-[var(--color-hairline)] shadow-sm">
        {loading && <Loading label="Reading assessments" />}

        {!loading && filtered.length === 0 && (
          <Empty
            label={
              rows.length === 0
                ? 'No assessments recorded. Upload a network configuration to begin.'
                : 'No assessment matches those filters.'
            }
          />
        )}

        {!loading && filtered.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[var(--color-hairline)] bg-[var(--color-cloud)] text-[11px] font-bold text-[var(--color-slate-gray)] select-none">
                  <th className="w-10 px-4 py-3.5 text-center">
                    <input type="checkbox" className="rounded border-[var(--color-hairline)] text-[#0a0a0a]" />
                  </th>
                  <th className="px-4 py-3.5 font-semibold">Assessment ID</th>
                  <th className="px-4 py-3.5 font-semibold">Device / Name</th>
                  <th className="px-4 py-3.5 font-semibold">Vendor / Platform</th>
                  <th className="px-4 py-3.5 font-semibold text-center">Compliance Score</th>
                  <th className="px-4 py-3.5 font-semibold">Findings</th>
                  <th className="px-4 py-3.5 font-semibold">Status</th>
                  <th className="px-4 py-3.5 font-semibold flex items-center gap-1">
                    Date <ChevronDown className="w-3 h-3" />
                  </th>
                  <th className="px-4 py-3.5 text-right font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-hairline)]">
                {filtered.map((item) => {
                  const isCompleted = item.score_pct >= 50;
                  const deviceClean = item.device.length > 25 ? item.device.slice(0, 20) + '...' : item.device;
                  const assessmentDisplayId = item.assessment_id.startsWith('NCSA') 
                    ? item.assessment_id 
                    : `NCSA-2026-${item.assessment_id.slice(0, 4).toUpperCase()}`;

                  return (
                    <tr
                      key={item.assessment_id}
                      onClick={() => navigate(`/assessments/${item.assessment_id}`)}
                      className="cursor-pointer transition-colors hover:bg-[var(--color-pebble)] group"
                    >
                      <td className="w-10 px-4 py-4 text-center" onClick={(e) => e.stopPropagation()}>
                        <input type="checkbox" className="rounded border-[var(--color-hairline)]" />
                      </td>

                      {/* Assessment ID */}
                      <td className="px-4 py-4">
                        <span className="font-bold text-[var(--color-ink-navy)] block group-hover:text-[var(--color-signal-blue)] transition-colors">
                          {assessmentDisplayId}
                        </span>
                        <span className="text-[10.5px] text-[var(--color-slate-gray)] block mt-0.5">
                          {item.vendor.toUpperCase()} Audit
                        </span>
                      </td>

                      {/* Device / Name */}
                      <td className="px-4 py-4">
                        <span className="font-bold text-[var(--color-ink-navy)] block">
                          {deviceClean}
                        </span>
                        <span className="text-[10.5px] text-[var(--color-slate-gray)] block mt-0.5">
                          Production Gateway
                        </span>
                      </td>

                      {/* Vendor / Platform */}
                      <td className="px-4 py-4">
                        <VendorBrand vendor={item.vendor} />
                      </td>

                      {/* Compliance Score */}
                      <td className="px-4 py-4 text-center">
                        <div className="inline-flex justify-center">
                          <ScoreRing score={item.score_pct} />
                        </div>
                      </td>

                      {/* Findings Indicators (4 dots: Critical, High, Medium, Low) */}
                      <td className="px-4 py-4">
                        <div className="flex items-center gap-2 text-[11px] font-semibold">
                          <span className="flex items-center gap-1 text-rose-600">
                            <span className="w-2 h-2 rounded-full bg-rose-500"></span> 2
                          </span>
                          <span className="flex items-center gap-1 text-orange-600">
                            <span className="w-2 h-2 rounded-full bg-orange-500"></span> 5
                          </span>
                          <span className="flex items-center gap-1 text-amber-600">
                            <span className="w-2 h-2 rounded-full bg-amber-500"></span> 12
                          </span>
                          <span className="flex items-center gap-1 text-slate-500">
                            <span className="w-2 h-2 rounded-full bg-slate-400"></span> 3
                          </span>
                        </div>
                      </td>

                      {/* Status Badge */}
                      <td className="px-4 py-4">
                        <span className={`px-2.5 py-1 text-[11px] font-semibold rounded-full border ${
                          isCompleted 
                            ? 'bg-blue-50 text-blue-700 border-blue-200' 
                            : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        }`}>
                          {isCompleted ? 'Completed' : 'In Progress'}
                        </span>
                      </td>

                      {/* Date */}
                      <td className="px-4 py-4 text-[11px] text-[var(--color-slate-gray)]">
                        <div>10 Sep 2026</div>
                        <div className="text-[10px] text-[var(--color-mist-gray)]">11:42 AM</div>
                      </td>

                      {/* Actions */}
                      <td className="px-4 py-4 text-right">
                        <ChevronRight className="inline w-4 h-4 text-[var(--color-mist-gray)] group-hover:text-[var(--color-ink-navy)] transition-colors" />
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

export default Assessments;

