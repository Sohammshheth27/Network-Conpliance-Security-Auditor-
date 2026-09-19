import { AlertTriangle, Info, Loader2, PlugZap } from "lucide-react";
import { cn } from "../../utils/cn";
import {
  ApiError,
  STATE_MEANING,
  STATE_STYLE,
  SEVERITY_STYLE,
  type ResultState,
  type Severity,
} from "../../lib/api";

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 py-10 justify-center text-[var(--color-slate-gray)] text-sm">
      <Loader2 className="h-4 w-4 animate-spin" />
      {label}...
    </div>
  );
}

export function ErrorPanel({
  error,
  onRetry,
}: {
  error: ApiError;
  onRetry?: () => void;
}) {
  const offline = error.status === 0;
  return (
    <div className="rounded-[16px] border border-[rgba(239,68,68,0.25)] bg-[rgba(239,68,68,0.05)] p-5">
      <div className="flex items-start gap-3">
        {offline ? (
          <PlugZap className="h-5 w-5 shrink-0 text-[#EF4444]" />
        ) : (
          <AlertTriangle className="h-5 w-5 shrink-0 text-[#EF4444]" />
        )}
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-[var(--color-ink-navy)]">
            {offline ? "Engine not reachable" : error.message}
          </p>
          {error.reason && (
            <p className="mt-1.5 text-[13px] leading-relaxed text-[var(--color-slate-gray)]">
              {error.reason}
            </p>
          )}
          {error.supportedPlatforms?.length ? (
            <p className="mt-2 text-[12.5px] text-[var(--color-mist-gray)]">
              Platforms that can answer this:{" "}
              <span className="text-[var(--color-slate-gray)]">
                {error.supportedPlatforms.join(" · ")}
              </span>
            </p>
          ) : null}
          {error.notAFinding && (
            <p className="mt-2 text-[12px] italic text-[var(--color-mist-gray)]">
              This is a gap in our coverage, not a statement about the device.
            </p>
          )}
          {offline && (
            <pre className="mt-3 overflow-x-auto rounded-lg border border-[var(--color-hairline)] bg-[var(--color-pebble)] px-3 py-2 text-[11.5px] text-[var(--color-ink-navy)] font-mono">
              uvicorn ncsa.api.app:app --port 8000
            </pre>
          )}
          {onRetry && (
            <button
              onClick={onRetry}
              className="mt-3 rounded-lg border border-[var(--color-hairline)] px-3 py-1.5 text-xs font-medium text-[var(--color-ink-navy)] bg-white transition-colors hover:bg-[var(--color-pebble)]"
            >
              Try again
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export function NotRun({
  what,
  reason,
  supported,
}: {
  what: string;
  reason?: string;
  supported?: string[];
}) {
  return (
    <div className="rounded-[16px] border border-[var(--color-hairline)] bg-white p-5 shadow-sm">
      <div className="flex items-start gap-3">
        <Info className="h-5 w-5 shrink-0 text-[var(--color-mist-gray)]" />
        <div className="min-w-0">
          <p className="text-sm font-semibold text-[var(--color-ink-navy)]">
            {what} was not run on this device
          </p>
          <p className="mt-1.5 text-[13px] leading-relaxed text-[var(--color-slate-gray)]">
            {reason ??
              "No rule-graph builder is registered for this platform, so the analysis could not be attempted."}
          </p>
          {supported?.length ? (
            <p className="mt-2 text-[12.5px] text-[var(--color-mist-gray)]">
              Supported today:{" "}
              <span className="text-[var(--color-slate-gray)]">{supported.join(" · ")}</span>
            </p>
          ) : null}
          <p className="mt-2 text-[12px] italic text-[var(--color-mist-gray)]">
            Zero findings here would mean "we looked and found nothing". This
            means we never looked — a gap in our coverage, not a clean result.
          </p>
        </div>
      </div>
    </div>
  );
}

export function Empty({ label }: { label: string }) {
  return (
    <div className="py-10 text-center text-sm text-[var(--color-mist-gray)]">{label}</div>
  );
}

export function StatePill({
  state,
  className,
}: {
  state: ResultState;
  className?: string;
}) {
  return (
    <span
      title={STATE_MEANING[state]}
      className={cn(
        "inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold tracking-wide",
        STATE_STYLE[state], // Note: You may need to update STATE_STYLE in api.ts to use light mode colors
        className,
      )}
    >
      {state.replace("_", " ")}
    </span>
  );
}

export function SeverityPill({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide",
        SEVERITY_STYLE[severity], // Note: You may need to update SEVERITY_STYLE in api.ts to use light mode colors
        className,
      )}
    >
      {severity}
    </span>
  );
}
