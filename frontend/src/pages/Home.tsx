import { type FC } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  FileText, 
  ShieldCheck, 
  CheckCircle2, 
  ChevronRight,
  Database,
  ArrowRight,
  PieChart
} from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Marquee } from '../components/ui/Marquee';
import { Loading } from '../components/ui/States';
import { api, vendorLabel, type AssessmentSummary } from '../lib/api';
import { useApi } from '../lib/useApi';

const Home: FC = () => {
  const navigate = useNavigate();

  const list = useApi<AssessmentSummary[]>(() => api.assessments(), [], { cacheKey: 'assessments' });
  const health = useApi(() => api.health(), [], { cacheKey: 'health' });
  const learned = useApi(() => api.learnedSummary(), [], { cacheKey: 'learned' });

  const rows = list.data ?? [];
  const recentAssessments = rows.slice().reverse().slice(0, 3);
  
  // Data-aware fallback handling
  const hasData = rows.length > 0;
  
  let complianceCoverage: string | number = '...';
  if (!list.loading) {
    if (rows.length > 0) {
      const avg = rows.reduce((sum, r) => sum + r.score_pct, 0) / rows.length;
      complianceCoverage = `${Math.round(avg)}%`;
    } else {
      complianceCoverage = "N/A";
    }
  }

  return (
    <div className="space-y-4 w-full">
      
      {/* 1. TOP SECTION: Asymmetric Overview + Recent Assessments */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
        {/* LEFT / MAIN (Cols 7 or 8): NCSA Hero Introduction Section */}
        <div className="lg:col-span-8">
          <Card className="h-full p-6 bg-white border border-[var(--color-hairline)] flex flex-col justify-between relative overflow-hidden">
            <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-center">
              {/* Left Column: Editorial Intro */}
              <div className="md:col-span-7 z-10">
                <span className="mb-1 block text-[10px] font-bold tracking-[0.25em] text-[var(--color-slate-gray)] uppercase">
                  M E R I D I A N
                </span>
                <h1 className="text-2xl sm:text-3xl lg:text-3xl font-bold tracking-tight text-[var(--color-ink-navy)] mb-1.5 leading-tight">
                  Network Security
                </h1>
                <p className="text-[var(--color-slate-gray)] text-sm font-medium mb-2.5">
                  Audits that build a safer tomorrow.
                </p>
                <p className="text-[var(--color-slate-gray)] text-[11px] sm:text-xs leading-relaxed mb-6 max-w-md">
                  Upload and audit your network configurations to identify risks, ensure compliance and strengthen your infrastructure.
                </p>

                <div className="flex flex-wrap items-center gap-3">
                  <Button 
                    onClick={() => navigate('/new-audit')} 
                    className="rounded-[8px] bg-[#0a0a0a] text-white hover:bg-[#222222] px-5 py-2.5 text-xs font-semibold flex items-center gap-2 shadow-sm transition-all"
                  >
                    <FileText className="w-3.5 h-3.5" />
                    Start New Audit
                  </Button>
                  <Button 
                    onClick={() => navigate('/assessments')} 
                    variant="ghost" 
                    className="rounded-[8px] bg-white border border-[var(--color-hairline)] text-[var(--color-ink-navy)] hover:bg-[var(--color-pebble)] px-5 py-2.5 text-xs font-semibold flex items-center gap-2 transition-all"
                  >
                    <FileText className="w-3.5 h-3.5" />
                    View Reports
                  </Button>
                </div>
              </div>

              {/* Right Column: Isometric Graphic + Audit Pipeline Stepper */}
              <div className="md:col-span-5 flex items-center justify-center md:justify-end">
                <div className="flex items-center gap-4">
                  {/* Isometric Graphic Cards */}
                  <div className="relative w-28 h-32 select-none hidden sm:block shrink-0">
                    {/* Back Card (Audit Report) */}
                    <div className="absolute top-2 right-0 w-20 h-28 rounded-xl bg-[var(--color-cloud)] border border-[var(--color-hairline)] shadow-sm transform -rotate-12 flex flex-col p-3 justify-between z-0 transition-transform hover:rotate-0">
                      <div className="flex items-center justify-between">
                        <div className="w-2 h-2 rounded-full bg-[var(--color-signal-blue)]"></div>
                        <div className="w-6 h-1.5 rounded-full bg-[var(--color-mist-gray)]/30"></div>
                      </div>
                      <div className="space-y-1.5 mt-2 flex-1">
                        <div className="w-full h-1.5 bg-[var(--color-mist-gray)]/30 rounded"></div>
                        <div className="w-4/5 h-1.5 bg-[var(--color-mist-gray)]/30 rounded"></div>
                        <div className="w-3/4 h-1.5 bg-[var(--color-mist-gray)]/30 rounded"></div>
                      </div>
                      <div className="w-6 h-6 rounded-full bg-[var(--color-pebble)] flex items-center justify-center self-end mt-1">
                        <ShieldCheck className="w-3.5 h-3.5 text-[var(--color-signal-blue)]" />
                      </div>
                    </div>

                    {/* Front Card (Secure Config) */}
                    <div className="absolute top-6 left-0 w-20 h-28 rounded-xl bg-[#0a0a0a] border border-[#222] text-white shadow-xl transform -rotate-3 flex flex-col p-3 justify-between z-10 transition-transform hover:rotate-0">
                      <div className="flex items-center justify-between">
                        <div className="w-2 h-2 rounded-full bg-[#10B981]"></div>
                        <div className="w-6 h-1.5 rounded-full bg-white/20"></div>
                      </div>
                      <div className="space-y-2 mt-3 flex-1">
                        <div className="w-full h-1.5 bg-white/20 rounded"></div>
                        <div className="w-5/6 h-1.5 bg-white/20 rounded"></div>
                        <div className="w-4/6 h-1.5 bg-white/20 rounded"></div>
                      </div>
                      <div className="w-6 h-6 rounded-full bg-white/10 flex items-center justify-center self-start mt-1">
                        <CheckCircle2 className="w-3.5 h-3.5 text-[#10B981]" />
                      </div>
                    </div>
                  </div>

                  {/* Vertical Audit Pipeline Stepper */}
                  <div className="flex flex-col gap-2.5 pl-2">
                    <div className="flex items-center gap-2 text-xs font-semibold text-[var(--color-ink-navy)]">
                      <div className="w-4 h-4 rounded-full bg-[#0a0a0a] text-white flex items-center justify-center">
                        <CheckCircle2 className="w-3 h-3 text-white" />
                      </div>
                      <span>Configuration</span>
                    </div>

                    <div className="flex items-center gap-2 text-xs font-semibold text-[var(--color-ink-navy)]">
                      <div className="w-4 h-4 rounded-full bg-[#0a0a0a] text-white flex items-center justify-center">
                        <CheckCircle2 className="w-3 h-3 text-white" />
                      </div>
                      <span>Analysis</span>
                    </div>

                    <div className="flex items-center gap-2 text-xs font-semibold text-[var(--color-ink-navy)]">
                      <div className="w-4 h-4 rounded-full border-2 border-[#0a0a0a] flex items-center justify-center">
                        <div className="w-1.5 h-1.5 rounded-full bg-[#0a0a0a]"></div>
                      </div>
                      <span>Findings</span>
                    </div>

                    <div className="flex items-center gap-2 text-xs font-medium text-[var(--color-slate-gray)]">
                      <div className="w-4 h-4 rounded-full border-2 border-[var(--color-mist-gray)]"></div>
                      <span>Compliance</span>
                    </div>

                    <div className="pt-2 border-t border-[var(--color-hairline)] mt-1">
                      <span className="text-[10.5px] text-[var(--color-slate-gray)] leading-tight block">
                        From configurations<br />to compliance.
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </Card>
        </div>

        {/* RIGHT (Cols 4): Recent Activity / Audits List */}
        <div className="lg:col-span-4 h-full">
          <Card className="h-[280px] p-0 bg-white border border-[var(--color-hairline)] flex flex-col">
            <div className="p-4 border-b border-[var(--color-hairline)] flex items-center justify-between">
              <h3 className="text-sm font-bold text-[var(--color-ink-navy)] flex items-center gap-2">
                Recent Assessments
                {hasData && (
                  <span className="bg-[var(--color-cloud)] text-[var(--color-slate-gray)] text-[10px] px-2 py-0.5 rounded-full font-bold">
                    {rows.length}
                  </span>
                )}
              </h3>
              <button 
                onClick={() => navigate('/assessments')}
                className="text-[11px] font-semibold text-[var(--color-slate-gray)] hover:text-[var(--color-ink-navy)] transition-colors"
              >
                View all
              </button>
            </div>
            
            <div className="flex-1 overflow-y-auto p-3 space-y-2">
              {list.loading && <Loading />}
              
              {!list.loading && !hasData && (
                <div className="h-full flex flex-col items-center justify-center text-center px-4">
                  <Database className="w-6 h-6 text-[var(--color-mist-gray)] mb-2" />
                  <p className="text-xs font-semibold text-[var(--color-ink-navy)]">No assessments yet</p>
                  <p className="text-[11px] text-[var(--color-slate-gray)] mt-1">Upload a configuration file to get started.</p>
                </div>
              )}

              {hasData && recentAssessments.map((r, idx) => {
                const deviceName = r.device || `Device ${idx + 1}`;
                const vendorClean = vendorLabel(r.vendor);
                const isPassed = r.score_pct >= 50;
                return (
                  <button
                    key={r.assessment_id || idx}
                    onClick={() => navigate(`/assessments/${r.assessment_id}`)}
                    className="w-full flex items-center justify-between p-3.5 rounded-xl border border-[var(--color-hairline)] bg-[var(--color-cloud)] hover:bg-[var(--color-pebble)] transition-all group text-left shadow-xs"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="w-8 h-8 rounded-lg bg-white border border-[var(--color-hairline)] flex items-center justify-center shrink-0">
                        <FileText className="w-4 h-4 text-[var(--color-slate-gray)]" />
                      </div>
                      <div className="flex flex-col min-w-0">
                        <span className="text-xs font-bold text-[var(--color-ink-navy)] truncate">
                          {deviceName}
                        </span>
                        <span className="text-[10.5px] text-[var(--color-slate-gray)] truncate">
                          {vendorClean}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 shrink-0">
                      <span className={`px-2 py-0.5 text-[10px] font-semibold rounded-full ${
                        isPassed 
                          ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' 
                          : 'bg-blue-50 text-blue-700 border border-blue-200'
                      }`}>
                        {isPassed ? 'Completed' : 'In Progress'}
                      </span>
                      <span className="text-xs font-bold text-[var(--color-ink-navy)]">
                        {Math.round(r.score_pct)}%
                      </span>
                      <ChevronRight className="w-3.5 h-3.5 text-[var(--color-mist-gray)] group-hover:text-[var(--color-ink-navy)] transition-colors" />
                    </div>
                  </button>
                );
              })}
            </div>
          </Card>
        </div>
      </div>

      {/* 2. SUBTLE EDITORIAL MARQUEE TICKER */}
      <Marquee className="rounded-xl" />

      {/* 3. SECOND SECTION: Key Insights & Infrastructure Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Key Insights (Cols 8) */}
        <div className="lg:col-span-8">
          <Card className="p-5 bg-white border border-[var(--color-hairline)] flex flex-col justify-between h-full">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold text-[var(--color-ink-navy)]">
                Key Insights
              </h3>
              <button 
                onClick={() => navigate('/analysis')}
                className="text-xs font-semibold text-[var(--color-ink-navy)] hover:text-[var(--color-signal-blue)] flex items-center gap-1 transition-colors"
              >
                View All <ArrowRight className="w-3 h-3" />
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {/* Insight 1: Active Sessions */}
              <button 
                onClick={() => navigate('/settings')}
                className="w-full text-left rounded-xl p-4 flex flex-col justify-between bg-[var(--color-cloud)] border border-[var(--color-hairline)] cursor-pointer hover:bg-[var(--color-pebble)] transition-all group focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500"
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="w-8 h-8 rounded-lg bg-[var(--color-pebble)] flex items-center justify-center text-[var(--color-signal-blue)]">
                    <Database className="w-4 h-4" />
                  </div>
                  <ChevronRight className="w-3.5 h-3.5 text-[var(--color-mist-gray)] group-hover:text-[var(--color-ink-navy)] transition-colors" />
                </div>
                <div>
                  <span className="text-[11px] font-semibold text-[var(--color-slate-gray)] block">
                    Active Sessions
                  </span>
                  <span className="text-2xl font-bold text-[var(--color-ink-navy)] block mt-0.5">
                    {health.loading ? '...' : health.data?.assessments ?? 0}
                  </span>
                  <span className="text-[10.5px] text-[var(--color-slate-gray)] mt-1 block">
                    In engine memory
                  </span>
                </div>
              </button>

              {/* Insight 2: Mappings Learned */}
              <button 
                onClick={() => navigate('/training')}
                className="w-full text-left rounded-xl p-4 flex flex-col justify-between bg-[var(--color-cloud)] border border-[var(--color-hairline)] cursor-pointer hover:bg-[var(--color-pebble)] transition-all group focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-signal-blue)]"
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="w-8 h-8 rounded-lg bg-[var(--color-pebble)] flex items-center justify-center text-[var(--color-ink-navy)]">
                    <FileText className="w-4 h-4" />
                  </div>
                  <ChevronRight className="w-3.5 h-3.5 text-[var(--color-mist-gray)] group-hover:text-[var(--color-ink-navy)] transition-colors" />
                </div>
                <div>
                  <span className="text-[11px] font-semibold text-[var(--color-slate-gray)] block">
                    Mappings Learned
                  </span>
                  <span className="text-2xl font-bold text-[var(--color-ink-navy)] block mt-0.5">
                    {learned.loading ? '...' : learned.data?.total ?? 0}
                  </span>
                  <span className="text-[10.5px] text-[var(--color-slate-gray)] mt-1 block">
                    From interactive training
                  </span>
                </div>
              </button>

              {/* Insight 3: Overall Compliance */}
              <button 
                onClick={() => navigate('/assessments')}
                className="w-full text-left rounded-xl p-4 flex flex-col justify-between bg-[var(--color-cloud)] border border-[var(--color-hairline)] cursor-pointer hover:bg-[var(--color-pebble)] transition-all group focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-signal-blue)]"
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="w-8 h-8 rounded-lg bg-[var(--color-pebble)] flex items-center justify-center text-[var(--color-ink-navy)]">
                    <PieChart className="w-4 h-4" />
                  </div>
                  <ChevronRight className="w-3.5 h-3.5 text-[var(--color-mist-gray)] group-hover:text-[var(--color-ink-navy)] transition-colors" />
                </div>
                <div>
                  <span className="text-[11px] font-semibold text-[var(--color-slate-gray)] block">
                    Avg Compliance Score
                  </span>
                  <span className="text-2xl font-bold text-[var(--color-ink-navy)] block mt-0.5">
                    {complianceCoverage}
                  </span>
                  <span className="text-[10.5px] text-[var(--color-slate-gray)] mt-1 block">
                    Based on available audits
                  </span>
                </div>
              </button>
            </div>
          </Card>
        </div>

        {/* Infrastructure Overview (Cols 4) */}
        <div className="lg:col-span-4 h-full flex">
          <Card className="p-6 bg-white border border-[var(--color-hairline)] w-full flex flex-col justify-between relative overflow-hidden">
            <div className="relative z-10">
              <h3 className="text-sm font-bold text-[var(--color-ink-navy)] mb-1">
                Quick Action
              </h3>
              <p className="text-sm sm:text-base font-bold text-[var(--color-ink-navy)] leading-snug mb-4 max-w-[240px]">
                Run a new audit to identify configuration risks and strengthen compliance.
              </p>
            </div>

            <div className="flex items-center justify-between mt-auto">
              <Button 
                onClick={() => navigate('/new-audit')} 
                className="rounded-[8px] bg-[#0a0a0a] text-white hover:bg-[#222222] px-5 py-2.5 text-xs font-semibold flex items-center gap-2 shadow-sm transition-all z-10"
              >
                <FileText className="w-3.5 h-3.5" />
                New Audit
              </Button>

              {/* Isometric Switch Appliance Graphic */}
              <div className="relative w-24 h-20 select-none pointer-events-none flex items-center justify-center">
                {/* Back document */}
                <div className="absolute top-0 right-2 w-12 h-16 bg-[var(--color-cloud)] border border-[var(--color-hairline)] rounded-lg transform rotate-12 shadow-sm flex flex-col p-1.5 gap-1">
                  <div className="w-4 h-1 bg-[var(--color-mist-gray)] rounded"></div>
                  <div className="w-8 h-0.5 bg-[var(--color-mist-gray)] rounded"></div>
                  <div className="w-6 h-0.5 bg-[var(--color-mist-gray)] rounded"></div>
                </div>
                {/* Front Appliance Box */}
                <div className="absolute bottom-1 right-5 w-16 h-10 bg-[#1e293b] rounded-md shadow-md transform -rotate-6 border border-[#334155] flex flex-col justify-between p-1.5">
                  <div className="flex items-center justify-between">
                    <div className="flex gap-0.5">
                      <div className="w-1 h-1 rounded-full bg-[#10B981]"></div>
                      <div className="w-1 h-1 rounded-full bg-[#10B981]"></div>
                    </div>
                    <div className="w-3 h-0.5 bg-slate-500 rounded"></div>
                  </div>
                  <div className="flex gap-1">
                    {[1, 2, 3, 4].map((p) => (
                      <div key={p} className="w-2 h-1.5 bg-[#0f172a] rounded-[1px] border border-slate-700"></div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default Home;
