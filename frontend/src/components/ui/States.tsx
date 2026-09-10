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

/**
 * The shared vocabulary for "we have no data".
 *
 * There are three genuinely different reasons, and the UI has to keep them
 * apart, because collapsing them is how absence starts reading as a positive
 * result:
 *
 *   Loading    -- we are still asking.
 *   NotRun     -- the analysis could not be attempted on this platform.
 *   ErrorPanel -- the request itself failed, or the engine refused.
 *
 * None of them renders an empty chart or a zero.
 */

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 py-10 justify-center text-[#8FA0BC] text-sm">
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
    <div className="rounded-[18px] border border-[rgba(229,72,77,0.28)] bg-[rgba(229,72,77,0.07)] p-5">
      <div className="flex items-start gap-3">
        {offline ? (
          <PlugZap className="h-5 w-5 shrink-0 text-[#E5484D]" />
        ) : (
          <AlertTriangle className="h-5 w-5 shrink-0 text-[#E5484D]" />
        )}
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-[#F5F8FF]">
            {offline ? "Engine not reachable" : error.message}
          </p>

          {/* An engine refusal carries WHY. Showing the status alone would
              leave the user to guess whether their upload was broken. */}
          {error.reason && (
            <p className="mt-1.5 text-[13px] leading-relaxed text-[#AAB8D0]">
              {error.reason}
            </p>
          )}

          {error.supportedPlatforms?.length ? (
            <p className="mt-2 text-[12.5px] text-[#8FA0BC]">
              Platforms that can answer this:{" "}
              <span className="text-[#F5F8FF]">
                {error.supportedPlatforms.join(" · ")}
              </span>
            </p>
          ) : null}

          {error.notAFinding && (
            <p className="mt-2 text-[12px] italic text-[#8FA0BC]">
              This is a gap in our coverage, not a statement about the device.
            </p>
          )}

          {offline && (
            <pre className="mt-3 overflow-x-auto rounded-lg border border-[rgba(100,150,220,0.18)] bg-[rgba(8,16,32,0.7)] px-3 py-2 text-[11.5px] text-[#AAB8D0]">
              uvicorn ncsa.api.app:app --port 8000
            </pre>
          )}

          {onRetry && (
            <button
              onClick={onRetry}
              className="mt-3 rounded-lg border border-[rgba(100,150,220,0.25)] px-3 py-1.5 text-xs font-medium text-[#F5F8FF] transition-colors hover:bg-[rgba(45,140,255,0.12)]"
            >
              Try again
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * The analysis never ran on this platform.
 *
 * Deliberately NOT an empty chart and NOT a zero. A zeroed rule-hygiene
 * summary reads as a spotless policy, which is the exact failure the engine
 * refuses to commit -- and it would be undone here, at the last layer, by a
 * component that shrugged.
 */
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
    <div className="rounded-[18px] border border-[rgba(100,150,220,0.18)] bg-[rgba(14,27,50,0.5)] p-5">
      <div className="flex items-start gap-3">
        <Info className="h-5 w-5 shrink-0 text-[#8FA0BC]" />
        <div className="min-w-0">
          <p className="text-sm font-semibold text-[#F5F8FF]">
            {what} was not run on this device
          </p>
          <p className="mt-1.5 text-[13px] leading-relaxed text-[#AAB8D0]">
            {reason ??
              "No rule-graph builder is registered for this platform, so the analysis could not be attempted."}
          </p>
          {supported?.length ? (
            <p className="mt-2 text-[12.5px] text-[#8FA0BC]">
              Supported today:{" "}
              <span className="text-[#F5F8FF]">{supported.join(" · ")}</span>
            </p>
          ) : null}
          <p className="mt-2 text-[12px] italic text-[#8FA0BC]">
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
    <div className="py-10 text-center text-sm text-[#8FA0BC]">{label}</div>
  );
}

/** A result-state chip. `title` carries the meaning, because these get misread. */
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
        STATE_STYLE[state],
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
        SEVERITY_STYLE[severity],
        className,
      )}
    >
      {severity}
    </span>
  );
}
