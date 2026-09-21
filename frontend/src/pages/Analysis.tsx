import { useState, type FC } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Network,
  Plus,
  Info,
  CheckCircle,
  AlertCircle,
  Map as MapIcon,
} from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { api, ApiError, type TopologyResponse } from '../lib/api';
import { useApi } from '../lib/useApi';
import { ErrorPanel, Loading, Empty } from '../components/ui/States';

const Analysis: FC = () => {
  const navigate = useNavigate();
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [topologyData, setTopologyData] = useState<TopologyResponse | null>(null);
  const [isBuilding, setIsBuilding] = useState(false);
  const [buildError, setBuildError] = useState<any>(null);

  const { data: assessments, loading, error, reload } = useApi(() => api.assessments(), [], { cacheKey: 'assessments' });

  const toggleSelection = (id: string) => {
    const next = new Set(selectedIds);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelectedIds(next);
  };

  const selectAll = () => {
    if (!assessments) return;
    if (selectedIds.size === assessments.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(assessments.map(a => a.assessment_id)));
    }
  };

  const buildTopology = async () => {
    if (selectedIds.size === 0) return;
    setIsBuilding(true);
    setBuildError(null);
    setTopologyData(null);
    try {
      const res = await api.topology(Array.from(selectedIds));
      setTopologyData(res);
    } catch (e: any) {
      setBuildError(new ApiError(500, (e as Error).message));
    } finally {
      setIsBuilding(false);
    }
  };

  return (
    <div className="space-y-6 max-w-[1440px] mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <span className="mb-1 block text-xs font-bold tracking-[0.25em] text-[var(--color-slate-gray)] uppercase">
            M E R I D I A N
          </span>
          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-[var(--color-ink-navy)]">
            Global Topology
          </h1>
          <p className="mt-1 text-xs sm:text-sm text-[var(--color-slate-gray)] font-medium">
            Stitch multiple assessments together to infer fleet-wide adjacency.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            className="flex items-center gap-2 text-xs font-semibold py-2.5 px-4 rounded-lg bg-[#0a0a0a] text-white hover:bg-[#222222] shadow-sm transition-all"
            onClick={() => navigate('/new-audit')}
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Audit</span>
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column - Selection */}
        <div className="lg:col-span-4 flex flex-col gap-4">
          <Card className="bg-white border border-[var(--color-hairline)] overflow-hidden flex-1 flex flex-col max-h-[600px]">
            <div className="p-4 border-b border-[var(--color-hairline)] bg-[var(--color-cloud)]/50 flex items-center justify-between">
              <h3 className="text-sm font-bold text-[var(--color-ink-navy)]">
                Select Devices
              </h3>
              <button 
                onClick={selectAll}
                className="text-[11px] font-semibold text-[var(--color-signal-blue)] hover:underline"
              >
                {assessments && selectedIds.size === assessments.length ? 'Deselect All' : 'Select All'}
              </button>
            </div>
            
            <div className="flex-1 overflow-y-auto p-2">
              {loading && <Loading label="Loading assessments..." />}
              {error && <ErrorPanel error={error} onRetry={reload} />}
              {!loading && !error && assessments?.length === 0 && (
                 <Empty label="No assessments available." />
              )}
              {assessments?.map(a => (
                <label 
                  key={a.assessment_id} 
                  className={`flex items-start gap-3 p-3 rounded-xl cursor-pointer transition-colors ${
                    selectedIds.has(a.assessment_id) ? 'bg-[var(--color-pebble)] border border-[var(--color-hairline)]' : 'hover:bg-[var(--color-cloud)] border border-transparent'
                  }`}
                >
                  <div className="pt-0.5">
                    <input 
                      type="checkbox" 
                      checked={selectedIds.has(a.assessment_id)}
                      onChange={() => toggleSelection(a.assessment_id)}
                      className="w-4 h-4 rounded border-gray-300 text-[var(--color-signal-blue)] focus:ring-[var(--color-signal-blue)]"
                    />
                  </div>
                  <div>
                    <div className="text-sm font-bold text-[var(--color-ink-navy)]">{a.device || a.assessment_id}</div>
                    <div className="text-[11px] font-medium text-[var(--color-slate-gray)] mt-0.5">
                      {a.vendor} {a.platform ? `· ${a.platform}` : ''}
                    </div>
                  </div>
                </label>
              ))}
            </div>

            <div className="p-4 border-t border-[var(--color-hairline)] bg-white">
               <Button 
                onClick={buildTopology} 
                disabled={selectedIds.size === 0 || isBuilding}
                className="w-full justify-center flex items-center gap-2"
               >
                 <Network className="w-4 h-4" />
                 {isBuilding ? 'Building...' : `Build Topology (${selectedIds.size})`}
               </Button>
            </div>
          </Card>
        </div>

        {/* Right Column - Results */}
        <div className="lg:col-span-8 flex flex-col gap-4">
          <Card className="bg-white border border-[var(--color-hairline)] p-6 min-h-[600px]">
            {!topologyData && !buildError && !isBuilding && (
              <div className="h-full flex flex-col items-center justify-center text-center opacity-60 mt-24">
                <MapIcon className="w-16 h-16 text-[var(--color-mist-gray)] mb-4" />
                <h3 className="text-lg font-bold text-[var(--color-ink-navy)]">No Topology Generated</h3>
                <p className="text-sm text-[var(--color-slate-gray)] max-w-md mt-2">
                  Select two or more devices from the left and click "Build Topology" to compute fleet-wide network adjacency.
                </p>
              </div>
            )}
            
            {isBuilding && (
              <div className="h-full flex items-center justify-center mt-24">
                <Loading label="Stitching topology data..." />
              </div>
            )}
            
            {buildError && (
              <ErrorPanel error={buildError} onRetry={buildTopology} />
            )}

            {topologyData && (
              <div className="space-y-6">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-[var(--color-cloud)] border border-[var(--color-hairline)] flex items-center justify-center">
                    <Info className="w-5 h-5 text-[var(--color-ink-navy)]" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-[var(--color-ink-navy)]">Topology Results</h3>
                    <p className="text-xs text-[var(--color-slate-gray)] font-medium mt-0.5">
                      Adjacency inferred from shared subnets across selected assessments.
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="p-4 rounded-xl border border-[var(--color-hairline)] bg-[var(--color-cloud)]">
                    <div className="text-2xl font-bold text-[var(--color-ink-navy)]">{topologyData.summary.devices}</div>
                    <div className="text-[11px] font-bold uppercase text-[var(--color-slate-gray)] mt-1">Devices</div>
                  </div>
                  <div className="p-4 rounded-xl border border-[var(--color-hairline)] bg-[var(--color-cloud)]">
                    <div className="text-2xl font-bold text-[var(--color-ink-navy)]">{topologyData.summary.interfaces}</div>
                    <div className="text-[11px] font-bold uppercase text-[var(--color-slate-gray)] mt-1">Interfaces</div>
                  </div>
                  <div className="p-4 rounded-xl border border-[var(--color-hairline)] bg-[var(--color-cloud)]">
                    <div className="text-2xl font-bold text-[var(--color-ink-navy)]">{topologyData.summary.links}</div>
                    <div className="text-[11px] font-bold uppercase text-[var(--color-slate-gray)] mt-1">Links</div>
                  </div>
                </div>

                {topologyData.skipped.length > 0 && (
                  <div className="mt-6">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--color-slate-gray)] mb-3">
                      Skipped Assessments
                    </h4>
                    <div className="space-y-2">
                      {topologyData.skipped.map((s, idx) => (
                        <div key={idx} className="flex items-start gap-2 p-3 rounded-xl bg-amber-50/50 border border-amber-100">
                          <AlertCircle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
                          <div>
                            <div className="text-xs font-bold text-[var(--color-ink-navy)]">{s.assessment_id}</div>
                            <div className="text-[11px] text-[var(--color-slate-gray)]">{s.reason}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="mt-6">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--color-slate-gray)] mb-3">
                    Stitched Devices
                  </h4>
                  <div className="space-y-2 max-h-[300px] overflow-y-auto">
                    {topologyData.devices.map((d, idx) => (
                      <div key={idx} className="flex items-center gap-2 p-3 rounded-xl border border-[var(--color-hairline)] bg-white">
                        <CheckCircle className="w-4 h-4 text-emerald-500" />
                        <span className="text-sm font-semibold text-[var(--color-ink-navy)]">{d.device}</span>
                        <span className="text-[11px] font-mono text-[var(--color-mist-gray)] ml-auto">{d.assessment_id}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {topologyData.explain && (
                  <div className="mt-6">
                     <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--color-slate-gray)] mb-3">
                      Analysis Output
                    </h4>
                    <pre className="p-4 rounded-xl border border-[var(--color-hairline)] bg-[#0a0a0a] text-emerald-400 font-mono text-[11px] overflow-x-auto">
                      {topologyData.explain}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
};

export default Analysis;
