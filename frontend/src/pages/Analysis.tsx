import { useState, type FC } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Upload,
  Plus,
  Info,
  Activity,
  Layers,
  Database,
  Search,
} from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { api } from '../lib/api';
import { useApi } from '../lib/useApi';

const Analysis: FC = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'findings' | 'engine'>('findings');
  
  const health = useApi(() => api.health(), [], { cacheKey: 'health' });

  return (
    <div className="space-y-6 max-w-[1440px] mx-auto">
      {/* 1. Header with Eyebrow, Title & Action Buttons matching image.png */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <span className="mb-1 block text-xs font-bold tracking-[0.25em] text-[var(--color-slate-gray)] uppercase">
            N C S A
          </span>
          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-[var(--color-ink-navy)]">
            Findings
          </h1>
          <p className="mt-1 text-xs sm:text-sm text-[var(--color-slate-gray)] font-medium">
            Review and analyse configuration issues identified across your network.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="ghost"
            className="flex items-center gap-2 text-xs font-semibold py-2.5 px-4 rounded-lg bg-white border border-[var(--color-hairline)] text-[var(--color-ink-navy)] hover:bg-[var(--color-pebble)] shadow-xs transition-all opacity-50 cursor-not-allowed"
            disabled
          >
            <Upload className="w-3.5 h-3.5 rotate-180" />
            <span>Export Report (Not Available)</span>
          </Button>

          <Button
            className="flex items-center gap-2 text-xs font-semibold py-2.5 px-4 rounded-lg bg-[#0a0a0a] text-white hover:bg-[#222222] shadow-sm transition-all"
            onClick={() => navigate('/new-audit')}
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Audit</span>
          </Button>
        </div>
      </div>

      {/* 2. Top-Level Tabs (Findings vs. Engine Capabilities) */}
      <div className="flex items-center gap-6 border-b border-[var(--color-hairline)] pt-2">
        <button
          onClick={() => setActiveTab('findings')}
          className={`pb-4 text-xs font-bold flex items-center gap-2 transition-all relative ${
            activeTab === 'findings'
              ? 'text-[var(--color-ink-navy)]'
              : 'text-[var(--color-slate-gray)] hover:text-[var(--color-ink-navy)]'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          Global Findings
          {activeTab === 'findings' && (
            <div className="absolute bottom-[-1px] left-0 right-0 h-0.5 bg-[var(--color-ink-navy)] rounded-t-full"></div>
          )}
        </button>

        <button
          onClick={() => setActiveTab('engine')}
          className={`pb-4 text-xs font-bold flex items-center gap-2 transition-all relative ${
            activeTab === 'engine'
              ? 'text-[var(--color-ink-navy)]'
              : 'text-[var(--color-slate-gray)] hover:text-[var(--color-ink-navy)]'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          Engine Capabilities
          {activeTab === 'engine' && (
            <div className="absolute bottom-[-1px] left-0 right-0 h-0.5 bg-[var(--color-ink-navy)] rounded-t-full"></div>
          )}
        </button>
      </div>

      {/* 3. Main Content Area */}
      {activeTab === 'findings' && (
        <Card className="bg-white border border-[var(--color-hairline)] overflow-hidden min-h-[400px] flex flex-col">
          {/* Findings Controls (Filters + Search) - Disabled visually for honest empty state */}
          <div className="p-4 border-b border-[var(--color-hairline)] bg-[var(--color-cloud)]/50 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-bold text-[var(--color-slate-gray)] tracking-wide uppercase mr-2">Filters</span>
              <div className="bg-white border border-[var(--color-hairline)] text-[var(--color-mist-gray)] text-xs font-semibold py-1.5 px-3 rounded-lg flex items-center gap-2 select-none opacity-60">
                Severity: All
              </div>
              <div className="bg-white border border-[var(--color-hairline)] text-[var(--color-mist-gray)] text-xs font-semibold py-1.5 px-3 rounded-lg flex items-center gap-2 select-none opacity-60">
                Device: All
              </div>
            </div>

            <div className="relative w-full md:w-64 opacity-60">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Search className="h-3.5 w-3.5 text-[var(--color-mist-gray)]" />
              </div>
              <input
                type="text"
                disabled
                placeholder="Search disabled..."
                className="block w-full pl-9 pr-3 py-1.5 bg-white border border-[var(--color-hairline)] rounded-lg text-xs placeholder-[var(--color-mist-gray)] text-[var(--color-ink-navy)] cursor-not-allowed"
              />
            </div>
          </div>

          <div className="flex-1 flex flex-col items-center justify-center p-12 text-center h-[350px]">
            <Database className="w-12 h-12 text-[var(--color-mist-gray)] mb-4" />
            <h3 className="text-base font-bold text-[var(--color-ink-navy)]">Global findings are not available yet</h3>
            <p className="text-sm text-[var(--color-slate-gray)] mt-2 max-w-md">
              The backend API does not currently support aggregating findings globally across all assessments. Findings are currently only available within individual assessments.
            </p>
            <Button 
              onClick={() => navigate('/assessments')} 
              variant="outline" 
              className="mt-6 font-semibold"
            >
              View Assessments
            </Button>
          </div>
        </Card>
      )}

      {activeTab === 'engine' && (
        <Card className="bg-white border border-[var(--color-hairline)] p-6 min-h-[400px]">
           <div className="flex items-center gap-3 mb-6">
              <div className="w-10 h-10 rounded-lg bg-[var(--color-cloud)] border border-[var(--color-hairline)] flex items-center justify-center">
                <Info className="w-5 h-5 text-[var(--color-ink-navy)]" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-[var(--color-ink-navy)]">Capability Matrix</h3>
                <p className="text-xs text-[var(--color-slate-gray)] font-medium mt-0.5">
                  Platform support status.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {health.loading && (
                <div className="col-span-full py-8 text-center text-sm font-medium text-[var(--color-slate-gray)]">
                  Loading engine capabilities...
                </div>
              )}
              {!health.loading && health.data?.platforms_parsed.map((plat) => (
                <div key={plat} className="p-4 rounded-xl border border-[var(--color-hairline)] bg-[var(--color-cloud)] flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
                  <span className="text-xs font-bold text-[var(--color-ink-navy)]">
                    {plat}
                  </span>
                </div>
              ))}
            </div>
        </Card>
      )}
    </div>
  );
};

export default Analysis;
