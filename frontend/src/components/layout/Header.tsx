import { Search, Bell } from 'lucide-react';
import { api } from '../../lib/api';
import { useApi } from '../../lib/useApi';

interface HeaderProps {
  searchQuery?: string;
  onSearchChange?: (val: string) => void;
}

export default function Header({ searchQuery = '', onSearchChange }: HeaderProps) {
  // The status light reports the engine, not a decoration. A hardcoded green
  // dot saying "online" while the backend is down is the smallest possible
  // version of the failure this whole product exists to avoid.
  const { data, error, loading } = useApi(() => api.health(), []);

  const state = loading
    ? { colour: '#F5B82E', label: 'Connecting to engine' }
    : error || !data?.ok
      ? { colour: '#E5484D', label: 'Engine offline' }
      : { colour: '#32D6A8', label: 'Analysis engine online' };

  return (
    <header className="z-20 flex h-16 select-none items-center justify-between px-6">
      <div className="relative w-full max-w-[420px]">
        <Search className="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-[#AAB8D0]" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange?.(e.target.value)}
          placeholder="Search assessments, devices, findings..."
          className="w-full rounded-full border border-[rgba(100,150,220,0.18)] bg-[rgba(11,21,40,0.85)] py-2 pl-11 pr-4 text-xs text-[#F5F8FF] shadow-[inset_0_1px_3px_rgba(0,0,0,0.4)] outline-none transition-all placeholder:text-[#65738B] focus:border-[#1677FF] md:text-sm"
        />
      </div>

      <div className="flex items-center gap-3.5">
        <div className="hidden items-center gap-2 rounded-full border border-[rgba(100,150,220,0.12)] bg-[rgba(14,27,50,0.6)] px-3 py-1.5 lg:flex">
          <span
            className="h-2 w-2 rounded-full"
            style={{
              backgroundColor: state.colour,
              boxShadow: `0 0 8px ${state.colour}`,
            }}
          />
          <span className="text-xs font-medium text-[#AAB8D0]">
            {state.label}
          </span>
          {data && (
            <span className="text-xs text-[#65738B]">
              · {data.platforms_parsed.length} platforms
            </span>
          )}
        </div>

        <button
          aria-label="Notifications"
          className="relative flex h-9 w-9 items-center justify-center rounded-full border border-[rgba(100,150,220,0.14)] bg-[rgba(14,27,50,0.8)] text-[#AAB8D0] transition-colors hover:border-[rgba(80,150,255,0.3)] hover:text-[#F5F8FF]"
        >
          <Bell className="h-4 w-4" />
        </button>

        {/* No signed-in user: this build has no authentication, and a profile
            pill showing a name would imply an identity nothing established. */}
        <div className="flex items-center gap-2.5 rounded-full border border-[rgba(100,150,220,0.18)] bg-[rgba(14,27,50,0.85)] py-1 pl-1.5 pr-3">
          <div className="flex h-7 w-7 items-center justify-center rounded-full bg-gradient-to-br from-[#1677FF] to-[#0B3A78] text-xs font-bold text-white shadow-[0_0_8px_rgba(22,119,255,0.4)]">
            N
          </div>
          <span className="text-xs font-medium text-[#F5F8FF]">Local</span>
        </div>
      </div>
    </header>
  );
}
