import { useEffect } from 'react';
import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom';
import AppShell from './components/layout/AppShell';
import Home from './pages/Home';
import Assessments from './pages/Assessments';
import AssessmentDetail from './pages/AssessmentDetail';
import NewAudit from './pages/NewAudit';
import Analysis from './pages/Analysis';
import Frameworks from './pages/Frameworks';
import Settings from './pages/Settings';
import Training from './pages/Training';

function ScrollToTop() {
  const { pathname } = useLocation();

  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "instant" });
  }, [pathname]);

  return null;
}

function App() {
  return (
    <BrowserRouter>
      <ScrollToTop />
      <Routes>
        <Route path="/" element={<AppShell />}>
          <Route index element={<Home />} />
          <Route path="assessments" element={<Assessments />} />
          <Route path="assessments/:id" element={<AssessmentDetail />} />
          <Route path="new-audit" element={<NewAudit />} />
          <Route path="training" element={<Training />} />
          <Route path="analysis" element={<Analysis />} />
          <Route path="frameworks" element={<Frameworks />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;

