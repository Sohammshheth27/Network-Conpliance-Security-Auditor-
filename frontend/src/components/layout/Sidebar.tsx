import { NavLink } from 'react-router-dom';
import { 
  Home, 
  Layers, 
  Plus, 
  BarChart3, 
  ShieldCheck, 
  Settings,
  GraduationCap 
} from 'lucide-react';
import { cn } from '../../utils/cn';


const primaryNav = [
  { name: 'Overview', to: '/', icon: Home },
  { name: 'Assessments', to: '/assessments', icon: Layers },
  { name: 'New Audit', to: '/new-audit', icon: Plus, isAction: true },
  { name: 'Training', to: '/training', icon: GraduationCap },
  { name: 'Analysis', to: '/analysis', icon: BarChart3 },
  { name: 'Frameworks', to: '/frameworks', icon: ShieldCheck },
];

export default function Sidebar() {
  return (
    <aside className="w-[230px] flex-shrink-0 flex flex-col py-6 px-4 select-none z-20">
      {/* Brand: Hexagonal Logo + Title */}
      <div className="flex items-center gap-3 px-3 mb-8">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#2D8CFF] to-[#0B3A78] p-[1px] shadow-[0_0_20px_rgba(22,119,255,0.4)] flex items-center justify-center">
          <div className="w-full h-full bg-[#0B1528] rounded-[11px] flex items-center justify-center">
            {/* Hexagon Shield Icon */}
            <svg className="w-6 h-6 text-[#2D8CFF]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" fill="rgba(22, 119, 255, 0.2)" />
              <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" />
            </svg>
          </div>
        </div>
        <div className="flex flex-col">
          <span className="font-bold text-base tracking-tight text-[#F5F8FF] leading-tight">NCSA</span>
          <span className="text-[10px] text-[#AAB8D0] font-medium leading-tight">
            Network Security<br />Compliance Auditor
          </span>
        </div>
      </div>

      {/* Main Nav Items */}
      <div className="flex-1 flex flex-col justify-between">
        <nav className="space-y-2">
          {primaryNav.map((item) => (
            <NavLink
              key={item.name}
              to={item.to}
              className={({ isActive }) => cn(
                "flex items-center gap-3 px-3.5 py-3 rounded-2xl text-sm font-medium transition-all duration-200",
                isActive 
                  ? "bg-gradient-to-r from-[#1677FF] to-[#2D8CFF] text-white shadow-[0_4px_20px_rgba(22,119,255,0.45)] font-semibold" 
                  : "text-[#AAB8D0] hover:text-[#F5F8FF] hover:bg-[rgba(14,27,50,0.6)]"
              )}
            >
              <item.icon className="w-[18px] h-[18px] flex-shrink-0" />
              <span>{item.isAction ? `+ ${item.name}` : item.name}</span>
            </NavLink>
          ))}
        </nav>

        {/* Bottom Section: Divider + Settings */}
        <div className="pt-4 border-t border-[rgba(100,150,220,0.12)]">
          <NavLink
            to="/settings"
            className={({ isActive }) => cn(
              "flex items-center gap-3 px-3.5 py-3 rounded-2xl text-sm font-medium transition-all duration-200",
              isActive 
                ? "bg-gradient-to-r from-[#1677FF] to-[#2D8CFF] text-white shadow-[0_4px_20px_rgba(22,119,255,0.45)] font-semibold" 
                : "text-[#AAB8D0] hover:text-[#F5F8FF] hover:bg-[rgba(14,27,50,0.6)]"
            )}
          >
            <Settings className="w-[18px] h-[18px] flex-shrink-0" />
            <span>Settings</span>
          </NavLink>
        </div>
      </div>
    </aside>
  );
}

