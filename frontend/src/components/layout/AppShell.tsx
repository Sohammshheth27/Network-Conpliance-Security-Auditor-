import { useEffect, useRef } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';

export default function AppShell() {
  const mainRef = useRef<HTMLElement | null>(null);
  const { pathname } = useLocation();

  useEffect(() => {
    mainRef.current?.scrollTo({
      top: 0,
      left: 0,
      behavior: 'auto',
    });
  }, [pathname]);

  return (
    <div className="h-screen bg-[var(--color-cloud)] text-[var(--color-ink-navy)] flex w-full font-sans overflow-hidden">
      {/* Left Vertical Rail Sidebar */}
      <Sidebar />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 bg-transparent h-full relative">
        <Header />
        <main ref={mainRef} className="flex-1 overflow-y-auto min-h-0 bg-[var(--color-cloud)]">
          <div key={pathname} className="animate-page-transition px-6 pb-6 pt-3 min-h-full">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
