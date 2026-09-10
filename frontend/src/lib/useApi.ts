import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "./api";

export interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: ApiError | null;
  reload: () => void;
}

/**
 * Run an engine call and expose loading / error / data.
 *
 * Errors are kept as ApiError rather than a string, because an engine refusal
 * carries structure the UI needs to render honestly -- the reason, and which
 * platforms could have answered. Flattening it to a message would throw that
 * away and leave the user staring at "422".
 */
export function useApi<T>(
  fn: () => Promise<T>,
  deps: unknown[],
  options: { enabled?: boolean } = {},
): AsyncState<T> {
  const enabled = options.enabled ?? true;
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(enabled);
  const [error, setError] = useState<ApiError | null>(null);
  const [nonce, setNonce] = useState(0);

  // The latest call wins. Without this a slow first request can land after a
  // fast second one and overwrite fresher data with staler data.
  const seq = useRef(0);

  useEffect(() => {
    if (!enabled) {
      setLoading(false);
      return;
    }
    const mine = ++seq.current;
    setLoading(true);
    setError(null);

    fn()
      .then((d) => {
        if (mine === seq.current) {
          setData(d);
          setLoading(false);
        }
      })
      .catch((e) => {
        if (mine !== seq.current) return;
        setError(
          e instanceof ApiError ? e : new ApiError(0, String(e?.message ?? e)),
        );
        setLoading(false);
      });
    // fn is intentionally not a dependency: callers pass an inline closure, and
    // including it would re-run on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce, enabled]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return { data, loading, error, reload };
}
