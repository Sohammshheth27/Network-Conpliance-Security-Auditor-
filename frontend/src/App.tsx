import { useEffect, useState, type ReactNode } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import AppShell from './components/layout/AppShell';
import Home from './pages/Home';
import Assessments from './pages/Assessments';
import AssessmentDetail from './pages/AssessmentDetail';
import NewAudit from './pages/NewAudit';
import Analysis from './pages/Analysis';
import HostFirewall from './pages/HostFirewall';
import Frameworks from './pages/Frameworks';
import Settings from './pages/Settings';
import Training from './pages/Training';
import Login from './pages/Login';
import { api, sessionToken } from './lib/api';

/**
 * Nothing behind the shell renders without a session.
 *
 * A token already in this tab is trusted optimistically so navigation does
 * not flash a check on every route change -- if it has expired, the first API
 * call returns 401 and `request()` sends the browser back here. With no token
 * the engine is asked whether it is enforcing sign-in at all, so a build
 * running against NCSA_CONSOLE_AUTH=0 is not locked out of its own console.
 */
function RequireAuth({ children }: { children: ReactNode }) {
  const [state, setState] = useState<'checking' | 'allowed' | 'denied'>(
    sessionToken() ? 'allowed' : 'checking',
  );

  useEffect(() => {
    if (state !== 'checking') return;
    let live = true;
    api
      .authStatus()
      .then((s) => live && setState(s.required && !s.authenticated ? 'denied' : 'allowed'))
      // The engine being unreachable is not an authentication failure. Let the
      // app load and show its own "cannot reach the engine" message, which
      // says something true, rather than a sign-in page that cannot work.
      .catch(() => live && setState('allowed'));
    return () => {
      live = false;
    };
  }, [state]);

  if (state === 'checking') {
    return <div className="min-h-screen bg-[var(--color-cloud)]" aria-busy="true" />;
  }
  if (state === 'denied') return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function App() {
  // The engine serves this app under a prefix (/dashboard), so the router has
  // to resolve its URLs against the same base Vite built with. Reading it from
  // BASE_URL keeps one build working both in dev (base "/") and when served by
  // the engine, with no second copy of the path to maintain.
  return (
    <BrowserRouter basename={import.meta.env.BASE_URL.replace(/\/$/, '')}>
      <Routes>
        {/* Outside the shell: there is no navigation to offer until someone
            has signed in. */}
        <Route path="/login" element={<Login />} />
        <Route
          path="/"
          element={
            <RequireAuth>
              <AppShell />
            </RequireAuth>
          }
        >
          <Route index element={<Home />} />
          <Route path="assessments" element={<Assessments />} />
          <Route path="assessments/:id" element={<AssessmentDetail />} />
          <Route path="new-audit" element={<NewAudit />} />
          <Route path="training" element={<Training />} />
          <Route path="analysis" element={<Analysis />} />
          <Route path="hostfw" element={<HostFirewall />} />
          <Route path="frameworks" element={<Frameworks />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
