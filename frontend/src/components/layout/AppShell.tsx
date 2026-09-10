import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';

export default function AppShell() {
  return (
    <div className="min-h-screen bg-[#060B18] text-[#F5F8FF] flex items-center justify-center p-3 sm:p-5 lg:p-7 relative overflow-x-hidden">
      {/* Subtle ambient lighting backdrop */}
      <div className="fixed top-0 left-1/4 w-[600px] h-[400px] bg-[#1677FF]/10 rounded-full blur-[140px] pointer-events-none -z-0" />
      <div className="fixed bottom-0 right-1/4 w-[500px] h-[350px] bg-[#0B3A78]/15 rounded-full blur-[130px] pointer-events-none -z-0" />

      {/* Primary Application Shell (Radius: 48px) */}
      <div className="w-full max-w-[1720px] min-h-[920px] ncsa-shell flex flex-col md:flex-row relative z-10 overflow-hidden">
        {/* Left Vertical Rail Sidebar */}
        <Sidebar />

        {/* Main Content Area */}
        <div className="flex-1 flex flex-col min-w-0 bg-transparent">
          <Header />
          <main className="flex-1 p-5 md:p-8 overflow-y-auto">
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  );
}

