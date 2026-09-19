import type { FC } from 'react';
import { Target, Activity } from 'lucide-react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { ErrorPanel, Loading } from '../ui/States';
import { api } from '../../lib/api';
import { useApi } from '../../lib/useApi';

export const AttackCoverage: FC = () => {
  const { data, loading, error, reload } = useApi(() => api.attackCoverage(), [], { cacheKey: 'attack-coverage' });

  return (
    <div className="space-y-6 mt-12">
      <div>
        <h2 className="text-xl font-semibold tracking-tight text-[var(--color-ink-navy)]">
          MITRE ATT&CK Coverage
        </h2>
        <p className="mt-1 text-[12.5px] text-[var(--color-slate-gray)] max-w-3xl">
          Which adversary techniques the compliance controls stand in front of. 
          ATT&CK describes the adversary; it is not a compliance framework, and no score is computed from it.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8 xl:col-span-9 space-y-6">
          <Card variant="default" className="p-6 bg-white">
            <h3 className="mb-4 text-sm font-bold uppercase tracking-wider text-[var(--color-ink-navy)]">
              Coverage Mapping
            </h3>
            
            {loading && <Loading label="Loading ATT&CK data..." />}
            {error && <ErrorPanel error={error} onRetry={reload} />}

            {data && (
              <>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
                   <div className="rounded-xl border border-[var(--color-hairline)] bg-[var(--color-cloud)] p-3">
                     <div className="flex items-center gap-2 mb-1">
                        <Target className="w-4 h-4 text-[var(--color-signal-blue)]" />
                        <span className="text-[11px] font-bold uppercase tracking-wider text-[var(--color-slate-gray)]">Techniques</span>
                     </div>
                     <span className="text-xl font-bold text-[var(--color-ink-navy)]">{data.techniques_covered.length}</span>
                   </div>
                   <div className="rounded-xl border border-[var(--color-hairline)] bg-[var(--color-cloud)] p-3">
                     <div className="flex items-center gap-2 mb-1">
                        <Activity className="w-4 h-4 text-emerald-600" />
                        <span className="text-[11px] font-bold uppercase tracking-wider text-[var(--color-slate-gray)]">Tactics</span>
                     </div>
                     <span className="text-xl font-bold text-[var(--color-ink-navy)]">{Object.keys(data.by_tactic).length}</span>
                   </div>
                   <div className="rounded-xl border border-[var(--color-hairline)] bg-[var(--color-cloud)] p-3">
                     <span className="block text-[11px] font-bold uppercase tracking-wider text-[var(--color-slate-gray)] mb-1">Tagged Controls</span>
                     <span className="text-xl font-bold text-[var(--color-ink-navy)]">{data.controls_tagged}</span>
                   </div>
                   <div className="rounded-xl border border-[var(--color-hairline)] bg-[var(--color-cloud)] p-3">
                     <span className="block text-[11px] font-bold uppercase tracking-wider text-[var(--color-slate-gray)] mb-1">Untagged</span>
                     <span className="text-xl font-bold text-[var(--color-ink-navy)]">{data.controls_untagged}</span>
                   </div>
                </div>
                
                <div className="space-y-4">
                  {Object.entries(data.by_tactic).map(([tactic, techniques]) => (
                    <div key={tactic} className="pb-4 border-b border-[var(--color-hairline)] last:border-0 last:pb-0">
                      <h4 className="text-[13px] font-bold text-[var(--color-ink-navy)] capitalize mb-2 flex items-center justify-between">
                         {tactic.replace(/-/g, ' ')}
                         <span className="text-[10px] text-[var(--color-mist-gray)] font-mono">{techniques.length} techniques</span>
                      </h4>
                      <div className="flex flex-wrap gap-1.5">
                         {techniques.map(t => (
                            <Badge key={t} variant="outline" className="font-mono bg-[var(--color-cloud)] border-[var(--color-hairline)] text-[var(--color-slate-gray)]">
                               {t}
                            </Badge>
                         ))}
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </Card>
        </div>
        
        <div className="lg:col-span-4 xl:col-span-3 space-y-4">
          <div className="p-4 rounded-2xl bg-[var(--color-pebble)] border border-[var(--color-hairline)] text-[11px] font-medium text-[var(--color-slate-gray)] leading-relaxed">
             <span className="font-bold text-[var(--color-ink-navy)] block mb-1">
               Why untagged controls?
             </span>
             {data?.untagged_reason || "Untagged controls prevent no specific adversary technique. Tagging them would be decoration."}
          </div>
          {data?.attack_version && (
            <div className="p-4 rounded-2xl bg-white border border-[var(--color-hairline)] text-[11px] font-medium text-[var(--color-slate-gray)] text-center">
              Using MITRE ATT&CK STIX Bundle Version <strong className="text-[var(--color-ink-navy)]">{data.attack_version}</strong>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
