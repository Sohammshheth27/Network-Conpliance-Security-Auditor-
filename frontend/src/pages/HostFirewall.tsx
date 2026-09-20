import { useState, useRef, type FC, type DragEvent } from 'react';
import { UploadCloud, Cpu, FileText } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { ErrorPanel, Loading, NotRun, Empty } from '../components/ui/States';
import { api, ApiError, type HygieneResponse } from '../lib/api';

const HostFirewall: FC = () => {
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [result, setResult] = useState<HygieneResponse | null>(null);

  const onDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragging(false);
    if (e.dataTransfer.files?.length) {
      setFile(e.dataTransfer.files[0]);
      setResult(null);
      setError(null);
    }
  };

  const runAudit = async () => {
    if (!file) return;
    setRunning(true);
    setError(null);
    setResult(null);
    try {
      const res = await api.assessIptables(file);
      setResult(res);
    } catch (e: any) {
      setError(e);
    } finally {
      setRunning(false);
    }
  };

  const runLocal = async () => {
    setRunning(true);
    setError(null);
    setResult(null);
    try {
      const res = await api.assessLocalHostfw(true);
      setResult(res);
    } catch (e: any) {
      setError(e);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div className="text-center sm:text-left">
        <span className="text-[11px] font-bold uppercase tracking-widest text-[var(--color-signal-blue)] block mb-1">
          NCSA AUDIT ENGINE
        </span>
        <h1 className="text-3xl font-semibold tracking-tight text-[var(--color-ink-navy)]">
          Host Firewall
        </h1>
        <p className="text-sm text-[var(--color-slate-gray)] mt-1">
          Upload an iptables-save dump to assess a Linux host firewall, or assess the local server running NCSA.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card variant="default" className="p-8 bg-white flex flex-col">
          <div
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            className={`border-2 border-dashed rounded-3xl p-8 text-center transition-all bg-[var(--color-cloud)] flex flex-col items-center justify-center ${
              dragging
                ? 'border-[var(--color-signal-blue)] bg-[rgba(0,107,255,0.05)]'
                : 'border-[var(--color-hairline)] hover:border-[var(--color-signal-blue)]'
            }`}
          >
            <UploadCloud className="w-8 h-8 text-[var(--color-signal-blue)] mb-4" />
            <h3 className="text-base font-bold text-[var(--color-ink-navy)] mb-1">
              Drop iptables-save output here
            </h3>
            <p className="text-xs text-[var(--color-slate-gray)] max-w-sm mb-5">
              Only one file at a time. Generates a one-off stateless hygiene report.
            </p>
            <input
              ref={inputRef}
              type="file"
              className="hidden"
              onChange={(e) => {
                if (e.target.files?.length) {
                  setFile(e.target.files[0]);
                  setResult(null);
                  setError(null);
                }
              }}
            />
            <button
              onClick={() => inputRef.current?.click()}
              className="ncsa-btn-primary px-5 py-2.5 rounded-full text-xs font-semibold"
            >
              Select File
            </button>
          </div>
          
          {file && (
             <div className="mt-4 p-3 rounded-xl border border-[var(--color-hairline)] bg-[var(--color-cloud)] flex items-center justify-between">
                <div className="flex items-center gap-2 min-w-0">
                  <FileText className="w-4 h-4 text-[var(--color-signal-blue)] shrink-0" />
                  <span className="text-sm font-bold text-[var(--color-ink-navy)] truncate">{file.name}</span>
                </div>
                <Button onClick={runAudit} disabled={running} className="text-xs py-1.5 px-3">
                   Assess File
                </Button>
             </div>
          )}
        </Card>

        <Card variant="default" className="p-8 bg-white flex flex-col items-center justify-center text-center">
            <Cpu className="w-12 h-12 text-[var(--color-mist-gray)] mb-4" />
            <h3 className="text-base font-bold text-[var(--color-ink-navy)] mb-2">Assess Local Host</h3>
            <p className="text-xs text-[var(--color-slate-gray)] max-w-sm mb-6">
              Assess the firewall of the machine RUNNING THIS API. Requires the API server to be running with appropriate privileges.
            </p>
            <Button onClick={runLocal} disabled={running} className="rounded-full px-6 py-2.5">
               Run Local Assessment
            </Button>
        </Card>
      </div>

      {running && (
        <Card className="p-6 text-center">
           <Loading label="Running rule hygiene assessment..." />
        </Card>
      )}

      {error && <ErrorPanel error={error} />}

      {result && (
         <div className="space-y-6">
            <h2 className="text-xl font-bold text-[var(--color-ink-navy)]">Hygiene Report</h2>
            <HygieneView data={result} />
         </div>
      )}
    </div>
  );
};

const HygieneView: FC<{ data: HygieneResponse }> = ({ data }) => {
  if (!data.analysis_ran || !data.summary) {
    return <NotRun what="Rule hygiene" reason={data.reason} supported={data.supported_platforms} />;
  }

  const s = data.summary;
  return (
    <div className="space-y-4">
      <Card variant="default" className="p-6">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            ['Rules examined', s.rules_examined],
            ['Fully resolved', s.rules_fully_resolved],
            ['Unevaluable', s.unevaluable],
            ['Findings', s.findings],
          ].map(([label, value]) => (
            <div key={label as string} className="rounded-xl border border-[var(--color-hairline)] p-3">
              <span className="block text-xl font-bold text-[var(--color-ink-navy)]">
                {(value as number).toLocaleString()}
              </span>
              <span className="text-[11px] text-[var(--color-slate-gray)]">{label}</span>
            </div>
          ))}
        </div>

        {s.unevaluable > 0 && (
          <p className="mt-4 rounded-xl border border-[rgba(245,184,46,0.25)] bg-[rgba(245,184,46,0.06)] p-3 text-[12.5px] text-[var(--color-slate-gray)]">
            <strong className="text-[#b45309]">
              {s.unevaluable} of {s.rules_examined} rules could not be fully resolved.
            </strong>{' '}
            Their references point at objects this export does not contain.
          </p>
        )}

        <div className="mt-4 flex flex-wrap gap-2">
          {Object.entries(s.by_kind).map(([kind, n]) => (
            <Badge key={kind} variant="outline">
              {kind.replace(/_/g, ' ')} · {n}
            </Badge>
          ))}
        </div>
      </Card>

      {data.findings.length > 0 ? (
        <Card variant="default" className="overflow-hidden p-0">
          <div className="border-b border-[var(--color-hairline)] p-4">
            <h4 className="text-sm font-bold text-[var(--color-ink-navy)]">
              Findings ({data.findings.length} shown)
            </h4>
          </div>
          <div className="max-h-[520px] overflow-y-auto">
            {data.findings.map((f, idx) => (
              <div key={idx} className="border-b border-[var(--color-hairline)] px-4 py-3 last:border-0">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant={f.severity === 'high' ? 'critical' : f.severity === 'medium' ? 'warning' : 'default'}>
                    {f.kind.replace(/_/g, ' ')}
                  </Badge>
                  <span className="font-mono text-[11.5px] text-[var(--color-ink-navy)]">{f.rule}</span>
                  {f.hit_count !== null && (
                    <span className="text-[11px] text-[var(--color-slate-gray)]">{f.hit_count.toLocaleString()} hits</span>
                  )}
                </div>
                <p className="mt-1 text-[12.5px] leading-relaxed text-[var(--color-slate-gray)]">{f.detail}</p>
              </div>
            ))}
          </div>
        </Card>
      ) : (
        <Empty label="No hygiene issues found." />
      )}
    </div>
  );
};

export default HostFirewall;
