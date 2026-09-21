import { Search, Bell, ChevronDown } from 'lucide-react';
import { sessionUser } from '../../lib/api';

interface HeaderProps {
  searchQuery?: string;
  onSearchChange?: (val: string) => void;
}

export default function Header({ searchQuery = '', onSearchChange }: HeaderProps) {
  // Falls back to the one account this console accepts, which is what is
  // shown when authentication is disabled for a local run.
  const who = sessionUser() || 'Administrator';
  const initial = who.charAt(0).toUpperCase();

  return (
    <header className="z-20 flex h-14 select-none items-center justify-between px-6 bg-transparent">
      {/* Left: Search Bar */}
      <div className="relative w-full max-w-[360px]">
        <Search className="absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--color-mist-gray)]" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange?.(e.target.value)}
          placeholder="Search devices, assessments, findings, rules, frameworks..."
          className="w-full rounded-full border border-[var(--color-hairline)] bg-white py-2 pl-10 pr-12 text-xs text-[var(--color-ink-navy)] shadow-xs outline-none transition-all placeholder:text-[var(--color-mist-gray)] focus:border-[var(--color-signal-blue)] focus:ring-1 focus:ring-[var(--color-signal-blue)] text-ellipsis whitespace-nowrap"
        />
        <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-0.5 pointer-events-none">
          <kbd className="rounded border border-[var(--color-hairline)] bg-[var(--color-pebble)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--color-slate-gray)] font-mono">
            ⌘ K
          </kbd>
        </div>
      </div>

      {/* Right: Notification, Language & Profile Area */}
      <div className="flex items-center gap-5">
        {/* Notification Bell */}
        <button
          aria-label="Notifications"
          className="relative flex h-9 w-9 items-center justify-center rounded-full text-[var(--color-slate-gray)] transition-colors hover:text-[var(--color-ink-navy)] hover:bg-[var(--color-pebble)]"
        >
          <Bell className="h-4 w-4 stroke-[1.8px]" />
          <span className="absolute top-2 right-2 h-2 w-2 rounded-full bg-red-500 ring-2 ring-white"></span>
        </button>

        {/* Language Selector */}
        <div className="flex items-center gap-1 text-xs font-semibold text-[var(--color-ink-navy)] cursor-pointer px-1 py-1 hover:text-[var(--color-signal-blue)]">
          <span>EN</span>
          <ChevronDown className="h-3.5 w-3.5 text-[var(--color-slate-gray)]" />
        </div>

        {/* User Profile */}
        <div className="flex items-center gap-2.5 pl-2 cursor-pointer group">
          <div className="h-8 w-8 rounded-full bg-[var(--color-pebble)] text-[var(--color-ink-navy)] font-bold text-xs flex items-center justify-center border border-[var(--color-hairline)]">
            {initial}
          </div>
          <div className="flex flex-col text-left">
            <span className="text-xs font-bold leading-none text-[var(--color-ink-navy)] group-hover:text-[var(--color-signal-blue)] transition-colors">
              {who}
            </span>
            {/* Not the role -- the console has exactly one -- but whether a
                session was actually presented. With NCSA_CONSOLE_AUTH=0 the
                name above is a default, and saying "signed in" would be a
                claim nobody made. */}
            <span className="text-[10px] text-[var(--color-slate-gray)] leading-tight mt-0.5">
              {sessionUser() ? 'Signed in' : 'Local access'}
            </span>
          </div>
          <ChevronDown className="h-3.5 w-3.5 text-[var(--color-slate-gray)] group-hover:text-[var(--color-ink-navy)] transition-colors ml-0.5" />
        </div>
      </div>
    </header>
  );
}
