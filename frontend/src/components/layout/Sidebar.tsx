import { useEffect, useRef, useState } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import { 
  Home, 
  Settings,
  LogOut,
  Layers, 
  Plus, 
  BarChart3, 
  ShieldCheck,
  GraduationCap,
  Monitor
} from 'lucide-react';
import { cn } from '../../utils/cn';
import { setSessionToken } from '../../lib/api';

const primaryNav = [
  { name: 'Dashboard', to: '/', icon: Home },
  { name: 'Assessments', to: '/assessments', icon: Layers },
  { name: 'New Audit', to: '/new-audit', icon: Plus, isAction: true },
  { name: 'Training', to: '/training', icon: GraduationCap },
  { name: 'Analysis', to: '/analysis', icon: BarChart3 },
  { name: 'Host Firewall', to: '/hostfw', icon: Monitor },
  { name: 'Frameworks', to: '/frameworks', icon: ShieldCheck },
  { name: 'Settings', to: '/settings', icon: Settings },
];

export default function Sidebar() {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const navRef = useRef<HTMLElement>(null);
  const [indicatorOffset, setIndicatorOffset] = useState<number | null>(null);

  useEffect(() => {
    if (!navRef.current) return;
    const activeEl = navRef.current.querySelector('[data-active="true"]') as HTMLElement;
    if (activeEl) {
      setIndicatorOffset(activeEl.offsetTop);
    }
  }, [pathname]);

  return (
    <aside className="w-[64px] h-[calc(100vh-32px)] my-4 ml-4 bg-[#0a0a0a] rounded-[28px] flex-shrink-0 flex flex-col py-6 select-none z-30 shadow-[0_20px_40px_-10px_rgba(0,0,0,0.3)]">
      {/* Brand / Logo Mark */}
      <div className="mb-10 w-full flex justify-center">
        <NavLink 
          to="/"
          className="w-10 h-10 bg-white rounded-full flex items-center justify-center transition-transform hover:scale-105 shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-signal-blue)] focus-visible:ring-offset-2 focus-visible:ring-offset-[#0a0a0a]"
          title="Meridian Overview"
        >
          {/* The mark: a sphere with its meridian cut out as negative space.
              A meridian is the fixed line a position is measured against,
              which is what this tool does to a configuration.

              Filled rather than stroked on purpose. Three hairlines at 20px
              close up into a smudge; a solid form with one clean cut stays
              legible down to a favicon. The cut is a lens, not a straight
              bar, because that is the shape a meridian plane actually makes
              when you view a sphere edge-on. */}
          {/* A sphere with its meridian struck through it in Signal Blue.
              A meridian is the fixed line a position is measured against,
              which is what this tool does to a configuration -- so the one
              coloured element is the reference, not decoration.

              Filled, and cut ONCE. An earlier version also cut the equator,
              which split the circle into four blobs and read as a fidget
              spinner at 20px. Three hairline strokes had the same problem
              from the other direction: they closed into a smudge. One solid
              form with one clean cut survives down to a 16px favicon. */}
          <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="12" r="9.5" fill="#0a0a0a" />
            <ellipse cx="12" cy="12" rx="3.7" ry="9.5" fill="#006bff" />
          </svg>
        </NavLink>
      </div>

      {/* Main Navigation Items */}
      <nav ref={navRef} className="relative flex-1 flex flex-col gap-2 w-full">
        {/* Persistent Animated Indicator */}
        {indicatorOffset !== null && (
          <div 
            className="absolute right-0 w-[calc(100%-12px)] h-12 bg-[var(--color-cloud)] rounded-l-[24px] pointer-events-none transition-transform duration-700 ease-[cubic-bezier(0.22,1,0.36,1)] will-change-transform"
            style={{ transform: `translate3d(0, ${indicatorOffset}px, 0)` }}
          >
            {/* Top inverse curve */}
            <div className="absolute -top-5 right-0 w-5 h-5 bg-[var(--color-cloud)] pointer-events-none">
              <div className="w-full h-full bg-[#0a0a0a] rounded-br-[20px]" />
            </div>
            
            {/* Bottom inverse curve */}
            <div className="absolute -bottom-5 right-0 w-5 h-5 bg-[var(--color-cloud)] pointer-events-none">
              <div className="w-full h-full bg-[#0a0a0a] rounded-tr-[20px]" />
            </div>
          </div>
        )}

        {primaryNav.map((item) => {
          const isActive = item.to === '/' ? pathname === '/' : pathname.startsWith(item.to);
          
          return (
            <div 
              key={item.name} 
              data-active={isActive} 
              className="relative w-full h-12 flex items-center shrink-0"
            >
              <NavLink
                to={item.to}
                title={item.name}
                className={cn(
                  "flex items-center justify-center transition-colors duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-signal-blue)] focus-visible:ring-offset-2 focus-visible:ring-offset-[#0a0a0a] z-10",
                  isActive 
                    ? "bg-transparent text-[#0a0a0a] rounded-l-[24px] w-[calc(100%-12px)] ml-auto h-full" 
                    : "text-white/75 hover:text-white w-10 h-10 rounded-[12px] mx-auto hover:bg-white/10"
                )}
              >
                <item.icon className="w-[18px] h-[18px] stroke-[2px]" />
              </NavLink>
            </div>
          );
        })}
      </nav>

      {/* Bottom Navigation / Action */}
      <div className="mt-auto pt-4 w-full flex justify-center">
        <button
          title="Sign out"
          className="w-12 h-12 rounded-[16px] flex items-center justify-center text-white/70 hover:text-white hover:bg-white/10 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-signal-blue)] focus-visible:ring-offset-2 focus-visible:ring-offset-[#0a0a0a]"
          onClick={() => {
            // This used to ask "Return to overview?" and navigate home, which
            // looked like signing out and was not. Dropping the session token
            // is what actually ends the session; the next API call has no
            // credential to present.
            if (window.confirm("Sign out of the Meridian console?")) {
              setSessionToken("");
              navigate("/login", { replace: true });
            }
          }}
        >
          <LogOut className="w-5 h-5 stroke-[1.8px]" />
        </button>
      </div>
    </aside>
  );
}

