import { useRef, useState, type DragEvent, type FC } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  UploadCloud,
  FileText,
  Play,
  ShieldCheck,
  Cpu,
  X,
  Eye,
  EyeOff,
} from 'lucide-react';

import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { ErrorPanel } from '../components/ui/States';
import { api, ApiError, vendorLabel, type PlatformInfo } from '../lib/api';
import { useApi } from '../lib/useApi';

import { CheckCircle2 } from 'lucide-react';
import LiveCollect from '../components/audit/LiveCollect';
function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// Simple Toast component for upload feedback
const Toast: FC<{ message: string; show: boolean }> = ({ message, show }) => {
  return (
    <div
      className={`fixed bottom-6 right-6 z-50 flex items-center gap-3 rounded-lg bg-[var(--color-ink-navy)] px-4 py-3 text-white shadow-xl transition-all duration-300 ${
        show ? 'translate-y-0 opacity-100' : 'translate-y-8 opacity-0 pointer-events-none'
      }`}
    >
      <CheckCircle2 className="h-5 w-5 text-[#10B981]" />
      <span className="text-sm font-medium">{message}</span>
    </div>
  );
};

const NewAudit: FC = () => {
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);

  const [files, setFiles] = useState<File[]>([]);
  const [dragging, setDragging] = useState(false);
  const [redact, setRedact] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [toastMessage, setToastMessage] = useState('');
  const [showToast, setShowToast] = useState(false);

  const triggerToast = (msg: string) => {
    setToastMessage(msg);
    setShowToast(true);
    setTimeout(() => setShowToast(false), 3000);
  };

  const { data: platforms } = useApi<PlatformInfo[]>(() => api.platforms(), [], { cacheKey: 'platforms' });

  const addFiles = (list: FileList | null) => {
    if (!list?.length) return;
    setFiles((prev) => [...prev, ...Array.from(list)]);
    triggerToast(`${list.length} file(s) added successfully`);
    setError(null);
  };

  const onDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragging(false);
    addFiles(e.dataTransfer.files);
  };

  const runAudit = async () => {
    if (!files.length) return;
    setRunning(true);
    setError(null);
    try {
      const results = await api.assess(files, redact);
      if (results.length === 1) navigate(`/assessments/${results[0].assessment_id}`);
      else navigate('/assessments');
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, String(e)));
    } finally {
      setRunning(false);
    }
  };

  const vendors = platforms
    ? [...new Set(platforms.map((p) => vendorLabel(p.vendor)))].join(', ')
    : null;

  return (
    <div className="space-y-6">
      <div className="text-center sm:text-left">
        <span className="text-[11px] font-bold uppercase tracking-widest text-[var(--color-signal-blue)] block mb-1">
          MERIDIAN AUDIT ENGINE
        </span>
        <h1 className="text-3xl font-semibold tracking-tight text-[var(--color-ink-navy)]">
          New Audit
        </h1>
        <p className="text-sm text-[var(--color-slate-gray)] mt-1">
          Upload a network or firewall configuration to begin compliance analysis.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
        {/* LEFT COLUMN: Dropzone and Live Collect */}
        <div className="flex flex-col gap-6 h-full">
          <Card variant="default" className="p-8 bg-white flex flex-col flex-1">
          <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          className={`border-2 border-dashed rounded-3xl p-8 sm:p-12 text-center transition-all bg-[var(--color-cloud)] flex flex-col items-center justify-center ${
            dragging
              ? 'border-[var(--color-signal-blue)] bg-[rgba(0,107,255,0.05)]'
              : 'border-[var(--color-hairline)] hover:border-[var(--color-signal-blue)]'
          }`}
        >
          <div className="w-16 h-16 rounded-2xl bg-[rgba(0,107,255,0.1)] border border-[rgba(0,107,255,0.2)] flex items-center justify-center text-[var(--color-signal-blue)] mb-4 shadow-sm">
            <UploadCloud className="w-8 h-8" />
          </div>

          <h3 className="text-base font-bold text-[var(--color-ink-navy)] mb-1">
            Drop a firewall or switch configuration here
          </h3>
          <p className="text-xs text-[var(--color-slate-gray)] max-w-lg mb-5 font-medium">
            {vendors
              ? `${platforms!.length} mapping packs loaded — ${vendors}. Several files at once are fine; each is assessed separately.`
              : 'Several files at once are fine; each is assessed separately.'}
          </p>

          <input
            ref={inputRef}
            type="file"
            multiple
            className="hidden"
            onChange={(e) => addFiles(e.target.files)}
          />
          <button
            onClick={() => inputRef.current?.click()}
            className="ncsa-btn-primary px-5 py-2.5 rounded-full text-xs font-semibold"
          >
            Select configuration files
          </button>
        </div>

        <div className="mt-6 pt-6 border-t border-[var(--color-hairline)]">
          <button
            onClick={() => setRedact(!redact)}
            className="flex items-start gap-3 text-left w-full group"
          >
            <span
              className={`mt-0.5 flex h-5 w-9 shrink-0 items-center rounded-full transition-colors ${
                redact ? 'bg-[var(--color-signal-blue)]' : 'bg-[var(--color-hairline)]'
              }`}
            >
              <span
                className={`h-4 w-4 rounded-full bg-white transition-transform ${
                  redact ? 'translate-x-4' : 'translate-x-0.5'
                }`}
              />
            </span>
            <span className="min-w-0">
              <span className="flex items-center gap-2 text-xs font-bold text-[var(--color-ink-navy)]">
                {redact ? (
                  <EyeOff className="w-3.5 h-3.5" />
                ) : (
                  <Eye className="w-3.5 h-3.5" />
                )}
                Redact addresses and secrets
                <Badge variant={redact ? 'success' : 'warning'}>
                  {redact ? 'ON' : 'OFF'}
                </Badge>
              </span>
              <span className="block text-[11.5px] font-medium text-[var(--color-slate-gray)] mt-1 leading-relaxed">
                {redact
                  ? 'Recommended. Note the trade-off: redaction removes interface addressing, so topology and multi-device path analysis cannot run on this upload.'
                  : 'Addresses are kept, which enables topology and path analysis. Use only on configurations you are permitted to handle unredacted.'}
              </span>
            </span>
          </button>
        </div>
      </Card>
      
      <LiveCollect redact={redact} frameworks={[]} />
      </div>

      {/* RIGHT COLUMN: Uploaded Files */}
      <Card variant="default" className="p-6 bg-white min-h-[300px] flex flex-col">
        {files.length > 0 ? (
          <>
            <div className="grid grid-cols-1 gap-3 flex-1 content-start">
              {files.map((f, i) => (
                <div
                  key={`${f.name}-${i}`}
                  className="flex items-center justify-between gap-4 p-3 rounded-xl border border-[var(--color-hairline)] bg-[var(--color-cloud)]"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="w-9 h-9 rounded-lg bg-white border border-[var(--color-hairline)] flex items-center justify-center text-[var(--color-signal-blue)] shrink-0">
                      <FileText className="w-4 h-4" />
                    </div>
                    <div className="min-w-0 flex flex-col">
                      <h4 className="text-sm font-bold text-[var(--color-ink-navy)] truncate">
                        {f.name}
                      </h4>
                      <span className="text-[10px] font-medium text-[var(--color-slate-gray)]">
                        {humanSize(f.size)}
                      </span>
                    </div>
                  </div>
                  <button
                    onClick={() => setFiles(files.filter((_, j) => j !== i))}
                    className="text-[var(--color-mist-gray)] hover:text-[#EF4444] transition-colors shrink-0 p-1"
                    aria-label={`Remove ${f.name}`}
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>

            <div className="mt-5 pt-5 border-t border-[var(--color-hairline)] flex items-center justify-between gap-4">
              <span className="text-xs font-medium text-[var(--color-slate-gray)]">
                {files.length} file{files.length > 1 ? 's' : ''} ready
              </span>
              <Button
                variant="primary"
                disabled={running}
                className="rounded-full px-6 py-3 font-semibold text-sm flex items-center gap-2"
                onClick={runAudit}
              >
                {running ? (
                  <>
                    <Cpu className="w-4 h-4 animate-spin text-white" />
                    <span>Assessing...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-current" />
                    <span>Run assessment</span>
                  </>
                )}
              </Button>
            </div>

            {running && (
              <div className="mt-5 p-4 rounded-2xl bg-[var(--color-cloud)] border border-[var(--color-signal-blue)] shadow-sm">
                <div className="flex items-center gap-3">
                  <span className="w-3 h-3 rounded-full bg-[var(--color-signal-blue)] animate-pulse" />
                  <span className="text-xs font-bold text-[var(--color-ink-navy)]">
                    Processing Batch Assessment...
                  </span>
                </div>
                <div className="w-full h-1.5 rounded-full bg-[var(--color-hairline)] overflow-hidden mt-3">
                  <div className="h-full w-1/3 bg-[var(--color-signal-blue)] animate-[ncsa-indeterminate_1.4s_ease-in-out_infinite]" />
                </div>
                <p className="text-[11px] font-medium text-[var(--color-slate-gray)] mt-2">
                  Submitting configuration files to the assessment engine.
                </p>
              </div>
            )}
          </>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center text-center p-6 text-[var(--color-mist-gray)]">
            <FileText className="w-8 h-8 mb-3 opacity-50" />
            <p className="text-sm font-medium text-[var(--color-slate-gray)]">No files selected</p>
            <p className="text-xs mt-1">Uploaded configurations will appear here.</p>
          </div>
        )}
      </Card>
      </div>

      {error && <ErrorPanel error={error} onRetry={runAudit} />}

      <div className="flex items-start gap-3 p-4 rounded-2xl bg-[var(--color-cloud)] border border-[var(--color-hairline)] text-xs font-medium text-[var(--color-slate-gray)]">
        <ShieldCheck className="w-4 h-4 text-[var(--color-signal-blue)] flex-shrink-0 mt-0.5" />
        <span>
          Assessment runs entirely on this machine. Configurations are parsed
          locally and nothing is transmitted off-premises. Copyrighted benchmark
          text is never emitted — CIS, ISO and PCI controls are cited by
          identifier only.
        </span>
      </div>

      <Toast message={toastMessage} show={showToast} />
    </div>
  );
};

export default NewAudit;
