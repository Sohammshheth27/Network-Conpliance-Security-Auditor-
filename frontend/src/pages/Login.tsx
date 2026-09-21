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
 * Built to design/NCSA_APP_DESIGN_SYSTEM.md: the .ncsa-card language, the
 * black brand mark from the sidebar rail, Signal Blue as the single primary
 * action, the 8px rhythm and the established page transition. No new radius,
 * colour, shadow or button style.
 *
 * IT MUST FIT ONE SCREEN WITHOUT SCROLLING, on a laptop as well as a desktop.
 * A sign-in page that scrolls is one where the button is below the fold, and
 * the first thing a new operator does is hunt for it. The whole layout is
 * built to a budget of roughly 600px:
 *
 *   - the brand sits BESIDE its title rather than above it, which is the
 *     single biggest saving (about 110px of pure vertical)
 *   - the QR is 200px, still comfortably scannable from a phone
 *   - card padding is 24px, the design system's own figure for card internals
 *
 * NOTE ON SPACING UTILITIES: the design system defines --spacing-8, -16, -24,
 * -32, -40, -48, -56, -64, -72 and -96 in @theme, which REDEFINES those
 * numeric utilities -- `p-8` is 8px, not 32px, and `w-56` is 56px, not 224px.
 * Every class here deliberately uses a number ABSENT from that list (3, 4, 6,
 * 11) so it resolves to the normal Tailwind scale, or an explicit pixel value.
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
      .catch(() => live && setError('Cannot reach the Meridian engine.'));
    return () => {
      live = false;
    };
  }, [navigate]);

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
      setError('Cannot reach the Meridian engine.');
    } finally {
      setBusy(false);
    }
  };

  const disabled = busy || locked > 0;
  const pairing = Boolean(enrollment);

  const form = (
    <form onSubmit={submit} className="ncsa-card p-6 h-full flex flex-col">
      <div className="flex items-center gap-2 mb-1">
        <LockKeyhole className="w-4 h-4 text-[var(--color-signal-blue)]" />
        <h2 className="text-[15px] font-bold">Sign in</h2>
        {pairing && <StepChip n={2} />}
      </div>
      <p className="mb-4 text-[12px] leading-[1.5] text-[var(--color-slate-gray)]">
        {pairing
          ? 'Then enter the code your authenticator shows.'
          : 'Enter your credentials and the current authenticator code.'}
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

      <div className="mb-3">
        <label
          htmlFor="otp"
          className="block text-[11px] leading-[1.4] font-semibold text-[var(--color-slate-gray)] mb-1.5"
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
          className="w-full h-11 px-3 rounded-[8px] border border-[var(--color-hairline)] bg-[var(--color-paper)] font-mono text-[18px] tracking-[0.4em] text-center text-[var(--color-ink-navy)] placeholder:text-[var(--color-mist-gray)] outline-none transition-colors focus:border-[var(--color-signal-blue)] focus:ring-2 focus:ring-[var(--color-signal-blue)]/20 disabled:bg-[var(--color-pebble)]"
        />
      </div>

      {error && (
        <p
          role="alert"
          className="mb-3 rounded-[8px] border border-[#EF4444]/25 bg-[#EF4444]/[0.08] px-3 py-1.5 text-[12px] leading-[1.4] text-[#EF4444]"
        >
          {error}
        </p>
      )}

      <button
        type="submit"
        disabled={disabled}
        className="ncsa-btn-primary mt-auto w-full h-11 text-[14px] font-semibold flex items-center justify-center gap-2 transition-transform active:scale-[0.98] disabled:opacity-50 disabled:active:scale-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-signal-blue)] focus-visible:ring-offset-2"
      >
        {busy && <Loader2 className="w-4 h-4 animate-spin" />}
        {locked > 0 ? `Locked — ${locked}s` : busy ? 'Verifying' : 'Sign in'}
      </button>

      {status && !status.required && (
        <p className="mt-2 text-[11px] leading-[1.4] text-[var(--color-slate-gray)]">
          Enforcement is off (<code className="font-mono">NCSA_CONSOLE_AUTH=0</code>).
        </p>
      )}
    </form>
  );

  return (
    // h-screen with overflow-hidden is the promise: this page does not scroll.
    // overflow-y-auto is kept as the escape hatch for a genuinely tiny window,
    // because an unreachable button is worse than a scrollbar.
    <div className="h-screen w-full overflow-y-auto bg-[var(--color-cloud)] text-[var(--color-ink-navy)] font-sans flex items-center justify-center px-6 py-6">
      <div
        className={`w-full animate-page-transition ${
          pairing ? 'max-w-[860px]' : 'max-w-[400px]'
        }`}
      >
        {/* Brand BESIDE the title, not above it. Stacked, this block cost
            about 160px of vertical; inline it costs about 50, which is the
            difference between fitting a laptop screen and not. */}
        <div className="flex items-center gap-3 mb-4">
          {/* The mark sits straight on the tile here. The sidebar nests it in
              a white chip because that chip is what lifts the brand off a
              black rail; repeating the chip on a black tile gave three
              concentric shapes -- square, ring, sphere -- and the eye reads
              the ring instead of the meridian. */}
          <div className="w-11 h-11 shrink-0 bg-[#0a0a0a] rounded-[14px] flex items-center justify-center shadow-[0_10px_24px_-8px_rgba(0,0,0,0.35)]">
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <circle cx="12" cy="12" r="9.5" fill="#ffffff" />
              <ellipse cx="12" cy="12" rx="3.7" ry="9.5" fill="#006bff" />
            </svg>
          </div>
          <div className="min-w-0">
            <h1 className="text-[20px] leading-[1.2] font-bold tracking-tight">Meridian</h1>
            <p className="text-[12px] leading-[1.4] text-[var(--color-slate-gray)] truncate">
              Network Compliance &amp; Security Auditor
            </p>
          </div>
        </div>

        {pairing ? (
          <div className="grid md:grid-cols-2 gap-4 items-stretch">
            <Pairing e={enrollment as AuthEnrollment} />
            {form}
          </div>
        ) : (
          form
        )}

        <p className="mt-3 text-center text-[11px] leading-[1.4] text-[var(--color-mist-gray)]">
          Local account with multi-factor authentication. Not single sign-on.
        </p>
      </div>
    </div>
  );
};

const StepChip: FC<{ n: number }> = ({ n }) => (
  <span className="ml-auto inline-flex items-center justify-center w-5 h-5 rounded-full bg-[var(--color-pebble)] border border-[var(--color-hairline)] text-[10px] font-bold text-[var(--color-slate-gray)]">
    {n}
  </span>
);

/**
 * First-run pairing.
 *
 * The QR is 200px. Big enough to scan from a phone held at arm's length,
 * small enough that the page still fits a laptop screen -- the earlier 240px
 * version pushed the sign-in button below the fold on a 1366x768 display.
 *
 * It is drawn by the engine and shown through <img> rather than injected as
 * markup, the rule the topology panel already follows, which also means the
 * console needs no QR library and works with no network.
 */
const Pairing: FC<{ e: AuthEnrollment }> = ({ e }) => (
  <div className="ncsa-card p-6 flex flex-col">
    <div className="flex items-center gap-2 mb-1">
      <ShieldCheck className="w-4 h-4 text-[var(--color-signal-blue)]" />
      <h2 className="text-[15px] font-bold">Pair your authenticator</h2>
      <StepChip n={1} />
    </div>
    <p className="mb-4 text-[12px] leading-[1.5] text-[var(--color-slate-gray)]">
      Scan once with Google Authenticator, Microsoft Authenticator, Authy,
      1Password or the RSA Authenticator app.
    </p>

    <div className="flex justify-center">
      <img
        src={`data:image/svg+xml;utf8,${encodeURIComponent(e.qr_svg)}`}
        alt="Pairing QR code for an authenticator app"
        width={200}
        height={200}
        // 200px on any normal screen, shrinking on a short one rather than
        // pushing the sign-in button below the fold. 150px is the floor:
        // below that a phone starts having to hunt for focus.
        className="w-[clamp(150px,30vh,200px)] h-[clamp(150px,30vh,200px)] rounded-[10px] border border-[var(--color-hairline)] bg-white p-2"
      />
    </div>

    <div className="mt-4">
      <p className="text-[11px] leading-[1.4] font-semibold text-[var(--color-slate-gray)] mb-1.5">
        Or enter this key by hand
      </p>
      <code className="block break-all font-mono text-[11px] leading-[1.5] text-[var(--color-ink-navy)] bg-[var(--color-pebble)] border border-[var(--color-hairline)] rounded-[8px] px-2 py-1.5">
        {e.secret}
      </code>
    </div>

    <p className="mt-3 text-[11px] leading-[1.4] text-[var(--color-mist-gray)]">
      RSA SecurID hardware tokens use a different scheme and cannot be paired
      here.
    </p>
  </div>
);

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
  <div className="mb-3">
    <label
      htmlFor={id}
      className="block text-[11px] leading-[1.4] font-semibold text-[var(--color-slate-gray)] mb-1.5"
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
      className="w-full h-11 px-3 rounded-[8px] border border-[var(--color-hairline)] bg-[var(--color-paper)] text-[14px] text-[var(--color-ink-navy)] outline-none transition-colors focus:border-[var(--color-signal-blue)] focus:ring-2 focus:ring-[var(--color-signal-blue)]/20 disabled:bg-[var(--color-pebble)]"
    />
  </div>
);

export default Login;
