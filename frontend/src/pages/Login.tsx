import {
  useEffect,
  useRef,
  useState,
  type FC,
  type FormEvent,
  type RefObject,
} from 'react';
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
 * Built to design/NCSA_APP_DESIGN_SYSTEM.md rather than around it: the
 * .ncsa-card language, the black brand mark from the sidebar rail, Signal Blue
 * as the single primary action, the 8px spacing scale and the established page
 * transition. No new radius, colour, shadow or button style is introduced.
 *
 * The page has two shapes. Paired, it is one narrow centred card -- the
 * invariants call NCSA "an operational auditing tool, not a consumer SaaS
 * app", and a returning operator wants three fields and an action. Unpaired,
 * it widens into two columns so the QR can be large enough to scan
 * comfortably from a phone held at arm's length, which a 128px code beside a
 * form is not.
 *
 * It is LOCAL AUTHENTICATION WITH MFA and the wording says so. Calling it
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
        if (s.authenticated) navigate('/', { replace: true });
        if (!s.enrolled) {
          try {
            const e = await api.authEnroll();
            if (live) setEnrollment(e);
          } catch {
            /* already paired elsewhere; the form still works */
          }
        }
      })
      .catch(() => live && setError('Cannot reach the NCSA engine.'));
    return () => {
      live = false;
    };
  }, [navigate]);

  // A lockout is a real wait, so it counts down rather than sitting on a
  // number that looks stuck.
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
  const pairing = Boolean(enrollment);

  const form = (
    <form onSubmit={submit} className="ncsa-card p-[32px] h-full flex flex-col">
      <div className="flex items-center gap-2">
        <LockKeyhole className="w-4 h-4 text-[var(--color-signal-blue)]" />
        <h2 className="text-[16px] font-bold">Sign in</h2>
        {pairing && <StepChip n={2} />}
      </div>
      <p className="mt-2 mb-6 text-[12px] leading-[1.5] text-[var(--color-slate-gray)]">
        {pairing
          ? 'Once your authenticator is paired, enter the code it shows.'
          : 'Enter your credentials and the current code from your authenticator.'}
      </p>

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
          className="w-full h-12 px-3 rounded-[8px] border border-[var(--color-hairline)] bg-[var(--color-paper)] font-mono text-[20px] tracking-[0.45em] text-center text-[var(--color-ink-navy)] placeholder:text-[var(--color-mist-gray)] outline-none transition-colors focus:border-[var(--color-signal-blue)] focus:ring-2 focus:ring-[var(--color-signal-blue)]/20 disabled:bg-[var(--color-pebble)]"
        />
        <p className="mt-2 text-[12px] leading-[1.5] text-[var(--color-mist-gray)]">
          Six digits, refreshed every 30 seconds.
        </p>
      </div>

      {error && (
        <p
          role="alert"
          className="mb-4 rounded-[8px] border border-[#EF4444]/25 bg-[#EF4444]/[0.08] px-3 py-2 text-[12px] leading-[1.5] text-[#EF4444]"
        >
          {error}
        </p>
      )}

      <button
        type="submit"
        disabled={disabled}
        className="ncsa-btn-primary mt-auto w-full h-12 text-[14px] font-semibold flex items-center justify-center gap-2 transition-transform active:scale-[0.98] disabled:opacity-50 disabled:active:scale-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-signal-blue)] focus-visible:ring-offset-2"
      >
        {busy && <Loader2 className="w-4 h-4 animate-spin" />}
        {locked > 0 ? `Locked — ${locked}s` : busy ? 'Verifying' : 'Sign in'}
      </button>

      {status && !status.required && (
        <p className="mt-4 text-[12px] leading-[1.5] text-[var(--color-slate-gray)]">
          Sign-in enforcement is disabled on this engine
          (<code className="font-mono">NCSA_CONSOLE_AUTH=0</code>), so the API
          will answer without a session.
        </p>
      )}
    </form>
  );

  return (
    <div className="min-h-screen w-full bg-[var(--color-cloud)] text-[var(--color-ink-navy)] font-sans flex items-center justify-center px-6 py-12">
      <div
        className={`w-full animate-page-transition ${
          pairing ? 'max-w-[900px]' : 'max-w-[420px]'
        }`}
      >
        {/* NOTE ON SPACING UTILITIES
            design/NCSA_APP_DESIGN_SYSTEM.md defines --spacing-8, -16, -24 …
            in @theme, which REDEFINES what Tailwind's numeric utilities mean:
            `p-8` resolves to 8px, not 32px, and `w-56` to 56px, not 224px.
            Numbers absent from that list (4, 6, 12) still fall through to the
            default scale. Explicit pixel values are used here where the two
            collide -- each one still lands on the system's own 8px rhythm,
            so this is not the arbitrary spacing the contract prohibits. */}
        <div className="flex flex-col items-center mb-[32px]">
          <div className="w-14 h-14 bg-[#0a0a0a] rounded-[20px] flex items-center justify-center shadow-[0_20px_40px_-10px_rgba(0,0,0,0.3)]">
            <div className="w-9 h-9 bg-white rounded-full flex items-center justify-center">
              <svg
                width="18"
                height="18"
                viewBox="0 0 24 24"
                fill="none"
                stroke="#0a0a0a"
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

        {pairing ? (
          <div className="grid md:grid-cols-2 gap-6 items-stretch">
            <Pairing e={enrollment as AuthEnrollment} />
            {form}
          </div>
        ) : (
          form
        )}

        <p className="mt-6 text-center text-[12px] leading-[1.5] text-[var(--color-mist-gray)]">
          Local account with multi-factor authentication. Not single sign-on —
          no external identity provider is involved.
        </p>
      </div>
    </div>
  );
};

/** The step number, so a first-time operator knows there are exactly two. */
const StepChip: FC<{ n: number }> = ({ n }) => (
  <span className="ml-auto inline-flex items-center justify-center w-6 h-6 rounded-full bg-[var(--color-pebble)] border border-[var(--color-hairline)] text-[11px] font-bold text-[var(--color-slate-gray)]">
    {n}
  </span>
);

/**
 * First-run pairing.
 *
 * The QR is 224px, not the 128px it started at: a code meant to be read by a
 * phone held away from the screen has to be comfortably larger than a
 * thumbnail, and this is the one moment the whole sign-in depends on working
 * first time.
 *
 * It is drawn by the engine and shown through <img> rather than injected as
 * markup -- the rule the topology panel already follows -- which also means
 * the console needs no QR library and works on a machine with no network.
 */
const Pairing: FC<{ e: AuthEnrollment }> = ({ e }) => (
  <div className="ncsa-card p-[32px] flex flex-col">
    <div className="flex items-center gap-2">
      <ShieldCheck className="w-4 h-4 text-[var(--color-signal-blue)]" />
      <h2 className="text-[16px] font-bold">Pair your authenticator</h2>
      <StepChip n={1} />
    </div>
    <p className="mt-2 mb-6 text-[12px] leading-[1.5] text-[var(--color-slate-gray)]">
      No authenticator is paired with this console yet. Scan this once with
      Google Authenticator, Microsoft Authenticator, Authy, 1Password or the
      RSA Authenticator app.
    </p>

    {/* 240px. This is the one moment the whole sign-in depends on working
        first time, and a code read by a phone held away from the screen has
        to be comfortably larger than a thumbnail. */}
    <div className="flex justify-center">
      <img
        src={`data:image/svg+xml;utf8,${encodeURIComponent(e.qr_svg)}`}
        alt="Pairing QR code for an authenticator app"
        width={240}
        height={240}
        className="w-[240px] h-[240px] rounded-[12px] border border-[var(--color-hairline)] bg-white p-[12px]"
      />
    </div>

    <div className="mt-6">
      <p className="text-[12px] leading-[1.5] font-semibold text-[var(--color-slate-gray)] mb-2">
        Or enter this key by hand
      </p>
      <code className="block break-all font-mono text-[12px] leading-[1.6] text-[var(--color-ink-navy)] bg-[var(--color-pebble)] border border-[var(--color-hairline)] rounded-[8px] px-3 py-2">
        {e.secret}
      </code>
    </div>

    {/* No icon: a phone glyph at this size renders as a bare rectangle and
        reads as a missing character, which undermines the one screen that has
        to look trustworthy. */}
    <p className="mt-4 text-[12px] leading-[1.5] text-[var(--color-mist-gray)]">
      RSA SecurID hardware tokens use a different scheme and cannot be paired
      here.
    </p>
  </div>
);

/** One labelled field, so the three of them cannot drift apart. */
const Field: FC<{
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  type?: string;
  autoComplete?: string;
  disabled?: boolean;
  inputRef?: RefObject<HTMLInputElement | null>;
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
      onChange={(ev) => onChange(ev.target.value)}
      className="w-full h-12 px-3 rounded-[8px] border border-[var(--color-hairline)] bg-[var(--color-paper)] text-[14px] text-[var(--color-ink-navy)] outline-none transition-colors focus:border-[var(--color-signal-blue)] focus:ring-2 focus:ring-[var(--color-signal-blue)]/20 disabled:bg-[var(--color-pebble)]"
    />
  </div>
);

export default Login;
