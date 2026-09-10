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

function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

const NewAudit: FC = () => {
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);

  const [files, setFiles] = useState<File[]>([]);
  const [dragging, setDragging] = useState(false);
  const [redact, setRedact] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  // The vendor list comes from the engine, so the "supported formats" line can
  // never drift from what the packs actually cover.
  const { data: platforms } = useApi<PlatformInfo[]>(() => api.platforms(), []);

  const addFiles = (list: FileList | null) => {
    if (!list?.length) return;
    setFiles((prev) => [...prev, ...Array.from(list)]);
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
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="text-center sm:text-left">
        <span className="text-[11px] font-bold uppercase tracking-widest text-[#2D8CFF] block mb-1">
          NCSA AUDIT ENGINE
        </span>
        <h1 className="text-3xl font-semibold tracking-tight text-[#F5F8FF]">
          New Audit
        </h1>
        <p className="text-sm text-[#AAB8D0] mt-1">
          Upload a network or firewall configuration to begin compliance analysis.
        </p>
      </div>

      <Card variant="default" className="p-8">
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          className={`border-2 border-dashed rounded-3xl p-8 sm:p-12 text-center transition-all bg-[rgba(11,21,40,0.4)] flex flex-col items-center justify-center ${
            dragging
              ? 'border-[#1677FF] bg-[rgba(22,119,255,0.08)]'
              : 'border-[rgba(100,150,220,0.22)] hover:border-[#1677FF]'
          }`}
        >
          <div className="w-16 h-16 rounded-2xl bg-[rgba(22,119,255,0.15)] border border-[rgba(80,150,255,0.3)] flex items-center justify-center text-[#2D8CFF] mb-4 shadow-[0_0_24px_rgba(22,119,255,0.3)]">
            <UploadCloud className="w-8 h-8" />
          </div>

          <h3 className="text-base font-bold text-[#F5F8FF] mb-1">
            Drop a firewall or switch configuration here
          </h3>
          <p className="text-xs text-[#AAB8D0] max-w-lg mb-5">
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

        {/* Redaction is a real engine parameter with a real consequence, so it
            is a control with its reason stated, not a silent default. */}
        <div className="mt-6 pt-6 border-t border-[rgba(100,150,220,0.12)]">
          <button
            onClick={() => setRedact(!redact)}
            className="flex items-start gap-3 text-left w-full group"
          >
            <span
              className={`mt-0.5 flex h-5 w-9 shrink-0 items-center rounded-full transition-colors ${
                redact ? 'bg-[#1677FF]' : 'bg-[rgba(100,150,220,0.25)]'
              }`}
            >
              <span
                className={`h-4 w-4 rounded-full bg-white transition-transform ${
                  redact ? 'translate-x-4' : 'translate-x-0.5'
                }`}
              />
            </span>
            <span className="min-w-0">
              <span className="flex items-center gap-2 text-xs font-semibold text-[#F5F8FF]">
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
              <span className="block text-[11.5px] text-[#8FA0BC] mt-1 leading-relaxed">
                {redact
                  ? 'Recommended. Note the trade-off: redaction removes interface addressing, so topology and multi-device path analysis cannot run on this upload.'
                  : 'Addresses are kept, which enables topology and path analysis. Use only on configurations you are permitted to handle unredacted.'}
              </span>
            </span>
          </button>
        </div>
      </Card>

      {files.length > 0 && (
        <Card variant="default" className="p-6">
          <div className="space-y-3">
            {files.map((f, i) => (
              <div
                key={`${f.name}-${i}`}
                className="flex items-center justify-between gap-4"
              >
                <div className="flex items-center gap-4 min-w-0">
                  <div className="w-11 h-11 rounded-2xl bg-[rgba(16,33,59,0.9)] border border-[rgba(100,150,220,0.2)] flex items-center justify-center text-[#2D8CFF] shrink-0">
                    <FileText className="w-5 h-5" />
                  </div>
                  <div className="min-w-0">
                    <h4 className="text-sm font-bold text-[#F5F8FF] font-mono truncate">
                      {f.name}
                    </h4>
                    {/* No "syntax verified" claim here: nothing has parsed it
                        yet. The vendor is identified by the engine's
                        fingerprinter, and it is shown once it has run. */}
                    <span className="text-xs text-[#8FA0BC]">
                      {humanSize(f.size)} · vendor detected on assessment
                    </span>
                  </div>
                </div>
                <button
                  onClick={() => setFiles(files.filter((_, j) => j !== i))}
                  className="text-[#8FA0BC] hover:text-[#E5484D] transition-colors shrink-0"
                  aria-label={`Remove ${f.name}`}
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>

          <div className="mt-5 pt-5 border-t border-[rgba(100,150,220,0.12)] flex items-center justify-between gap-4">
            <span className="text-xs text-[#8FA0BC]">
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
            <div className="mt-5 p-4 rounded-2xl bg-[rgba(14,27,50,0.85)] border border-[rgba(80,150,255,0.3)]">
              <div className="flex items-center gap-3">
                <span className="w-3 h-3 rounded-full bg-[#2D8CFF] animate-pulse" />
                <span className="text-xs font-semibold text-[#F5F8FF]">
                  Fingerprint → mapping pack → parse → baseline model → 81 rules
                </span>
              </div>
              {/* An indeterminate bar, because the engine reports no progress
                  percentage. A bar that crept to 100% on a timer would be
                  inventing information. */}
              <div className="w-full h-1.5 rounded-full bg-[rgba(22,119,255,0.2)] overflow-hidden mt-3">
                <div className="h-full w-1/3 bg-gradient-to-r from-[#1677FF] to-[#32D6A8] animate-[ncsa-indeterminate_1.4s_ease-in-out_infinite]" />
              </div>
              <p className="text-[11px] text-[#8FA0BC] mt-2">
                Large exports take a moment — a 2.7 MB SonicWall backup is
                ~90,000 records.
              </p>
            </div>
          )}
        </Card>
      )}

      {error && <ErrorPanel error={error} onRetry={runAudit} />}

      <div className="flex items-start gap-3 p-4 rounded-2xl bg-[rgba(14,27,50,0.4)] border border-[rgba(100,150,220,0.1)] text-xs text-[#AAB8D0]">
        <ShieldCheck className="w-4 h-4 text-[#2D8CFF] flex-shrink-0 mt-0.5" />
        <span>
          Assessment runs entirely on this machine. Configurations are parsed
          locally and nothing is transmitted off-premises. Copyrighted benchmark
          text is never emitted — CIS, ISO and PCI controls are cited by
          identifier only.
        </span>
      </div>
    </div>
  );
};

export default NewAudit;
