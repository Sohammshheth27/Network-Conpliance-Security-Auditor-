import { useEffect, useRef, useState, type FC, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { Loader2, LockKeyhole, ShieldCheck } from 'lucide-react';
import {
  api,
  setSessionToken,
  type AuthEnrollment,
  type AuthStatus,
} from '../lib/api';

/**
 * Console sign-in.
 *
 * Built to the NCSA design contract rather than around it: the card language,
 * the black brand mark from the sidebar rail, Signal Blue as the single
 * primary action, the 8px spacing scale, and the established page transition.
 * No new radius, colour, shadow or button style is introduced here.
 *
 * Deliberately restrained. The design invariants call NCSA "an operational
 * auditing tool, not a consumer SaaS app", so this is one centred card with
 * the brand, three fields and one action -- not a marketing splash.
 *
 * It is LOCAL AUTHENTICATION WITH MFA, and the wording says so. Calling it
 * single sign-on would claim a federation to an identity provider that does
 * not exist here.
 */
const Login: FC = () => {
  const navigate = useNavigate();
  const [status, setStatus] = useState<AuthStatus | null>(null);
  const [enrollment, setEnrollment] = useState<AuthEnrollment | null>(null);
  const [username, setUsername] = useState('Administrator');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [locked, setLocked] = useState(0);
  const passwordRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    let live = true;
    api
      .authStatus()
      .then(async (s) => {
        if (!live) return;
        setStatus(s);
        setLocked(s.locked_seconds);
        // Already signed in on this tab: nothing to do here.
        if (s.authenticated) navigate('/', { replace: true });
        // First run — show the pairing code before anyone can sign in.
        if (!s.enrolled) {
          try {
            const e = await api.authEnroll();
            if (live) setEnrollment(e);
          } catch {
            /* already paired by someone else; the form still works */
          }
        }
      })
      .catch(() => live && setError('Cannot reach the NCSA engine.'));
    return () => {
      live = false;
    };
  }, [navigate]);

  // The lockout is a real wait, so it is shown counting down rather than as a
  // static number that looks stuck.
  useEffect(() => {
    if (locked <= 0) return;
    const t = setInterval(() => setLocked((s) => Math.max(0, s - 1)), 1000);
    return () => clearInterval(t);
  }, [locked]);

  useEffect(() => {
    passwordRef.current?.focus();
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy || locked > 0) return;
    setBusy(true);
    setError('');
    try {
      const r = await api.login(username, password, otp);
      if (r.ok && r.token) {
        setSessionToken(r.token);
        navigate('/', { replace: true });
        return;
      }
      setError(r.detail || 'Sign-in failed.');
      setLocked(r.locked_seconds || 0);
      setOtp('');
    } catch {
      setError('Cannot reach the NCSA engine.');
    } finally {
      setBusy(false);
    }
  };

  const disabled = busy || locked > 0;

  return (
    <div className="min-h-screen w-full bg-[var(--color-cloud)] text-[var(--color-ink-navy)] font-sans flex items-center justify-center px-6 py-12">
      <div className="w-full max-w-[420px] animate-page-transition">
        {/* Brand mark — the rail's logo treatment, so the console is
            recognisable before any of it has loaded. */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-14 h-14 bg-[#0a0a0a] rounded-[20px] flex items-center justify-center shadow-[0_20px_40px_-10px_rgba(0,0,0,0.3)]">
            <div className="w-9 h-9 bg-white rounded-full flex items-center justify-center">
              <svg
                className="w-4.5 h-4.5 text-[#0a0a0a]"
                width="18"
                height="18"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <path d="M12 3L2 20h20L12 3z" />
              </svg>
            </div>
          </div>
          <h1 className="mt-4 text-[28px] leading-[1.4] font-bold tracking-tight">NCSA</h1>
          <p className="text-[14px] leading-[1.4] text-[var(--color-slate-gray)]">
            Network Compliance &amp; Security Auditor
          </p>
        </div>

        {/* First run: pair an authenticator before the first sign-in. */}
        {enrollment && <Enrollment e={enrollment} />}

        <form onSubmit={submit} className="ncsa-card p-8">
          <div className="flex items-center gap-2 mb-6">
            <LockKeyhole className="w-4 h-4 text-[var(--color-signal-blue)]" />
            <h2 className="text-[16px] font-bold">Sign in</h2>
          </div>

          <Field
            id="username"
            label="Username"
            value={username}
            onChange={setUsername}
            autoComplete="username"
            disabled={disabled}
          />

          <Field
            id="password"
            label="Password"
            type="password"
            value={password}
            onChange={setPassword}
            autoComplete="current-password"
            disabled={disabled}
            inputRef={passwordRef}
          />

          <div className="mb-6">
            <label
              htmlFor="otp"
              className="block text-[12px] leading-[1.5] font-semibold text-[var(--color-slate-gray)] mb-2"
            >
              Authentication code
            </label>
            <input
              id="otp"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              placeholder="000000"
              value={otp}
              disabled={disabled}
              onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
              className="w-full h-11 px-3 rounded-[8px] border border-[var(--color-hairline)] bg-[var(--color-paper)] font-mono text-[18px] tracking-[0.4em] text-center text-[var(--color-ink-navy)] placeholder:text-[var(--color-mist-gray)] placeholder:tracking-[0.4em] outline-none transition-colors focus:border-[var(--color-signal-blue)] focus:ring-2 focus:ring-[var(--color-signal-blue)]/20 disabled:bg-[var(--color-pebble)]"
            />
            <p className="mt-2 text-[12px] leading-[1.5] text-[var(--color-mist-gray)]">
              Six digits from your authenticator app.
            </p>
          </div>

          {error && (
            <p
              role="alert"
              className="mb-4 rounded-[8px] border border-[#EF4444]/25 bg-[#EF4444]/8 px-3 py-2 text-[12px] leading-[1.5] text-[#EF4444]"
            >
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={disabled}
            className="ncsa-btn-primary w-full h-11 text-[14px] font-semibold flex items-center justify-center gap-2 transition-transform active:scale-[0.98] disabled:opacity-50 disabled:active:scale-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-signal-blue)] focus-visible:ring-offset-2"
          >
            {busy && <Loader2 className="w-4 h-4 animate-spin" />}
            {locked > 0 ? `Locked — ${locked}s` : busy ? 'Verifying' : 'Sign in'}
          </button>

          {status && !status.required && (
            <p className="mt-4 text-[12px] leading-[1.5] text-[var(--color-slate-gray)]">
              Sign-in enforcement is currently disabled on this engine
              (<code className="font-mono">NCSA_CONSOLE_AUTH=0</code>), so the
              API will answer without a session.
            </p>
          )}
        </form>

        <p className="mt-6 text-center text-[12px] leading-[1.5] text-[var(--color-mist-gray)]">
          Local account with multi-factor authentication. Not single sign-on —
          no external identity provider is involved.
        </p>
      </div>
    </div>
  );
};

/** One labelled text field, so the three of them cannot drift apart. */
const Field: FC<{
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  type?: string;
  autoComplete?: string;
  disabled?: boolean;
  inputRef?: React.RefObject<HTMLInputElement | null>;
}> = ({ id, label, value, onChange, type = 'text', autoComplete, disabled, inputRef }) => (
  <div className="mb-4">
    <label
      htmlFor={id}
      className="block text-[12px] leading-[1.5] font-semibold text-[var(--color-slate-gray)] mb-2"
    >
      {label}
    </label>
    <input
      id={id}
      ref={inputRef}
      type={type}
      value={value}
      autoComplete={autoComplete}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value)}
      className="w-full h-11 px-3 rounded-[8px] border border-[var(--color-hairline)] bg-[var(--color-paper)] text-[14px] text-[var(--color-ink-navy)] outline-none transition-colors focus:border-[var(--color-signal-blue)] focus:ring-2 focus:ring-[var(--color-signal-blue)]/20 disabled:bg-[var(--color-pebble)]"
    />
  </div>
);

/**
 * First-run pairing.
 *
 * The QR is drawn by the engine and shown through <img> rather than injected
 * as markup — the same rule the topology panel follows. It also means the
 * console needs no QR library and works on a machine with no network.
 */
const Enrollment: FC<{ e: AuthEnrollment }> = ({ e }) => (
  <div className="ncsa-card p-6 mb-4">
    <div className="flex items-center gap-2 mb-2">
      <ShieldCheck className="w-4 h-4 text-[var(--color-signal-blue)]" />
      <h2 className="text-[14px] font-bold">Pair your authenticator</h2>
    </div>
    <p className="text-[12px] leading-[1.5] text-[var(--color-slate-gray)] mb-4">
      No authenticator is paired yet. Scan this once, then sign in with the
      code it shows.
    </p>
    <div className="flex items-start gap-4">
      <img
        src={`data:image/svg+xml;utf8,${encodeURIComponent(e.qr_svg)}`}
        alt="Pairing QR code for the authenticator app"
        className="w-32 h-32 shrink-0 rounded-[8px] border border-[var(--color-hairline)] bg-white p-1"
      />
      <div className="min-w-0">
        <p className="text-[12px] leading-[1.5] font-semibold text-[var(--color-slate-gray)] mb-1">
          Or enter this key by hand
        </p>
        <code className="block break-all font-mono text-[12px] text-[var(--color-ink-navy)] bg-[var(--color-pebble)] rounded-[8px] px-2 py-1.5">
          {e.secret}
        </code>
        <p className="mt-2 text-[12px] leading-[1.5] text-[var(--color-mist-gray)]">
          {e.note}
        </p>
      </div>
    </div>
  </div>
);

export default Login;
