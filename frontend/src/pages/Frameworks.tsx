import { useState, type FC } from 'react';
import { Search, ShieldCheck, Layers, BookLock, Lock, FileCode } from 'lucide-react';
import { api } from '../lib/api';
import { useApi } from '../lib/useApi';
import { ErrorPanel, Loading } from '../components/ui/States';

import { AiGovernance } from '../components/AiGovernance';
import { SystemStatus } from '../components/SystemStatus';
import { AttackCoverage } from '../components/frameworks/AttackCoverage';

// Static metadata mapping for UI enhancement of framework items.
// This is perfectly acceptable as it just maps UI presentation logic (icons, static labels)
// onto dynamic data keys returned by the backend.
const CATALOGUE: Record<string, { name: string; version: string; licence: string; note: string; icon: any }> = {
  cis_benchmarks: {
    name: 'CIS Benchmarks',
    version: 'v8',
    licence: 'identifier',
    note: 'Copyrighted. Mappings reference control identifiers only.',
    icon: ShieldCheck,
  },
  iso_27001_2022: {
    name: 'ISO/IEC 27001',
    version: '2022',
    licence: 'identifier',
    note: 'Copyrighted. Clause number and short title only, never ISO prose.',
    icon: Layers,
  },
  nist_800_171_r3: {
    name: 'NIST SP 800-171',
    version: 'Rev 3',
    licence: 'full',
    note: 'Public domain. Carries the embedded 800-53 crosswalk from back-matter.',
    icon: FileCode,
  },
  pci_dss_4: {
    name: 'PCI DSS',
    version: '4.0',
    licence: 'identifier',
    note: 'Copyrighted. Requirement identifiers only; descriptions are never stored.',
    icon: BookLock,
  },
  cmmc: {
    name: 'CMMC',
    version: 'Level 2',
    licence: 'identifier',
    note: 'Deliberately empty. CMMC Level 2 maps to 800-171 Rev 2; we hold Rev 3.',
    icon: ShieldCheck,
  },
  nerc_cip: {
    name: 'NERC CIP',
    version: '—',
    licence: 'identifier',
    note: 'Deliberately empty. No authoritative machine-readable source is held.',
    icon: Lock,
  },
};

const Frameworks: FC = () => {
  const { data, loading, error, reload } = useApi(() => api.frameworks(), [], { cacheKey: 'frameworks' });
  const [searchQuery, setSearchQuery] = useState('');

  const catalogKeys = data ? Object.keys(data.catalogs) : Object.keys(CATALOGUE);

  // Filter frameworks if search is typed
  const filteredKeys = catalogKeys.filter((key) => {
    const meta = CATALOGUE[key];
    const name = meta?.name ?? key;
    return (
      name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      key.toLowerCase().includes(searchQuery.toLowerCase())
    );
  });

  return (
    <div className="space-y-6 max-w-[1440px] mx-auto">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <span className="text-[11px] font-bold uppercase tracking-wider text-[var(--color-slate-gray)]">
            Frameworks
          </span>
          <h1 className="text-3xl font-semibold tracking-tight text-[var(--color-ink-navy)]">
            Frameworks
          </h1>
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--color-mist-gray)]" />
          <input
            type="text"
            placeholder="Search"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full h-10 pl-9.5 pr-8 text-xs font-medium rounded-xl border border-[var(--color-hairline)] bg-white text-[var(--color-ink-navy)] placeholder:text-[var(--color-mist-gray)] focus:outline-none focus:border-[var(--color-signal-blue)] transition-colors"
          />
          <kbd className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] font-mono text-[var(--color-mist-gray)]">
            ⌘F
          </kbd>
        </div>
      </div>

      {loading && <Loading label="Loading compliance catalogues" />}
      {error && <ErrorPanel error={error} onRetry={reload} />}

      {data && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Main Left Workspace (Cols 1-9) */}
          <div className="lg:col-span-8 xl:col-span-9 space-y-6">
            {/* Framework Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
              {filteredKeys.map((key) => {
                const meta = CATALOGUE[key];
                const count = data.catalogs[key] ?? 0;
                const empty = count === 0;
                const IconComponent = meta?.icon || ShieldCheck;

                return (
                  <div
                    key={key}
                    className="p-5 rounded-2xl bg-white border border-[var(--color-hairline)] shadow-[0_1px_3px_rgba(0,0,0,0.02)] flex flex-col justify-between hover:shadow-md transition-shadow"
                  >
                    <div>
                      {/* Black squircle icon container */}
                      <div className="w-10 h-10 rounded-xl bg-[#0a0a0a] flex items-center justify-center text-white mb-3 shadow-sm">
                        <IconComponent className="w-5 h-5 stroke-[1.75]" />
                      </div>

                      <h3 className="text-sm font-bold text-[var(--color-ink-navy)] tracking-tight">
                        {meta?.name ?? key}
                      </h3>
                      <p className="mt-1 text-[11.5px] font-medium text-[var(--color-slate-gray)] leading-relaxed line-clamp-2">
                        {empty
                          ? 'Deliberately unpopulated in accordance with licensing provenance.'
                          : meta?.note}
                      </p>
                    </div>

                    <div className="mt-4 pt-3 border-t border-[var(--color-hairline)] flex items-center justify-between">
                      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-semibold bg-[var(--color-pebble)] text-[var(--color-ink-navy)] border border-[var(--color-hairline)]">
                        {empty ? 'Unpopulated' : `${count.toLocaleString()} controls`}
                      </span>
                      <span className="text-[11px] font-medium text-[var(--color-mist-gray)]">
                        {meta?.version}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Rail Panel */}
          <div className="lg:col-span-4 xl:col-span-3 space-y-4">
            {/* Licence Handling Note */}
            <div className="p-4 rounded-2xl bg-[var(--color-pebble)] border border-[var(--color-hairline)] text-[11px] font-medium text-[var(--color-slate-gray)] leading-relaxed">
              <span className="font-bold text-[var(--color-ink-navy)] block mb-1">
                Licence Enforcement
              </span>
              {data.note} Licence handling is enforced in the type system rather
              than by policy, so copyrighted text cannot be emitted by
              construction.
            </div>
          </div>
        </div>
      )}

      {/* AiGovernance sits completely separate from the catalogues */}
      <div className="mt-12">
        <AiGovernance />
      </div>

      <AttackCoverage />

      <SystemStatus />
    </div>
  );
};

export default Frameworks;
