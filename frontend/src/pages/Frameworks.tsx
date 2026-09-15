import { type FC } from 'react';
import { BookLock, ShieldCheck } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { ErrorPanel, Loading } from '../components/ui/States';
import { api } from '../lib/api';
import { useApi } from '../lib/useApi';
import { AiGovernance } from '../components/AiGovernance';

/**
 * Catalogue metadata the engine does not carry.
 *
 * The API returns sizes; the licence posture and the reason a catalogue is
 * empty live here because they are presentation, not measurement. The counts
 * themselves always come from the engine.
 */
const CATALOGUE: Record<
  string,
  { name: string; version: string; licence: 'full' | 'identifier'; note: string }
> = {
  nist_800_53: {
    name: 'NIST SP 800-53',
    version: 'Rev 5',
    licence: 'full',
    note: 'US government work, public domain. Control text is stored and shown in full.',
  },
  disa_stig: {
    name: 'DISA STIG',
    version: 'Current',
    licence: 'full',
    note: 'Public domain. Provides the STIG → CCI → 800-53 provenance chain.',
  },
  cis: {
    name: 'CIS Benchmarks',
    version: 'Multiple',
    licence: 'identifier',
    note: 'Copyrighted. Cited by recommendation number and benchmark title only; the text never leaves this machine.',
  },
  iso_27001_2022: {
    name: 'ISO/IEC 27001',
    version: '2022',
    licence: 'identifier',
    note: 'Copyrighted. Clause number and short title only, never ISO prose.',
  },
  nist_800_171_r3: {
    name: 'NIST SP 800-171',
    version: 'Rev 3',
    licence: 'full',
    note: 'Public domain. Carries the embedded 800-53 crosswalk from its own back-matter.',
  },
  pci_dss_4: {
    name: 'PCI DSS',
    version: '4.0',
    licence: 'identifier',
    note: 'Copyrighted. Requirement identifiers only; descriptions are never stored.',
  },
  cmmc: {
    name: 'CMMC',
    version: 'Level 2',
    licence: 'identifier',
    note: 'Deliberately empty. CMMC Level 2 maps to 800-171 Rev 2 (110 requirements); we hold Rev 3 (130). Deriving one from the other would be wrong, so it is left unpopulated rather than approximated.',
  },
  nerc_cip: {
    name: 'NERC CIP',
    version: '—',
    licence: 'identifier',
    note: 'Deliberately empty. No authoritative machine-readable source is held, and inventing one would put unverified control text into an audit.',
  },
};

const Frameworks: FC = () => {
  const { data, loading, error, reload } = useApi(() => api.frameworks(), []);

  const total = data
    ? Object.values(data.catalogs).reduce((a, b) => a + b, 0)
    : 0;

  return (
    <div className="space-y-6">
      <div>
        <span className="mb-1 block text-[11px] font-bold uppercase tracking-widest text-[#2D8CFF]">
          NCSA COMPLIANCE FRAMEWORKS
        </span>
        <h1 className="text-3xl font-semibold tracking-tight text-[#F5F8FF]">
          Frameworks
        </h1>
        <p className="mt-1 text-sm text-[#AAB8D0]">
          Every finding carries its provenance: STIG → CCI → NIST 800-53 → ISO
          27001, and → 800-171.
        </p>
      </div>

      {loading && <Loading label="Loading catalogues" />}
      {error && <ErrorPanel error={error} onRetry={reload} />}

      {data && (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <Card variant="panel" className="flex items-center gap-4">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[rgba(22,119,255,0.15)] text-[#2D8CFF]">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <div>
                <span className="block text-xs font-medium text-[#AAB8D0]">
                  Controls indexed
                </span>
                <span className="text-xl font-bold text-[#F5F8FF]">
                  {total.toLocaleString()}
                </span>
              </div>
            </Card>
            <Card variant="panel" className="flex items-center gap-4">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[rgba(50,214,168,0.15)] text-[#32D6A8]">
                <BookLock className="h-5 w-5" />
              </div>
              <div>
                <span className="block text-xs font-medium text-[#AAB8D0]">
                  Catalogues
                </span>
                <span className="text-xl font-bold text-[#F5F8FF]">
                  {Object.keys(data.catalogs).length}
                </span>
              </div>
            </Card>
            <Card variant="panel" className="flex items-center gap-4">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[rgba(245,184,46,0.15)] text-[#F5B82E]">
                <BookLock className="h-5 w-5" />
              </div>
              <div>
                <span className="block text-xs font-medium text-[#AAB8D0]">
                  Identifier-only
                </span>
                <span className="text-xl font-bold text-[#F5F8FF]">
                  {
                    Object.keys(data.catalogs).filter(
                      (k) => CATALOGUE[k]?.licence === 'identifier',
                    ).length
                  }
                </span>
              </div>
            </Card>
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {Object.entries(data.catalogs).map(([key, count]) => {
              const meta = CATALOGUE[key];
              const empty = count === 0;
              return (
                <Card key={key} variant="default" className="p-5">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <h3 className="text-base font-bold text-[#F5F8FF]">
                        {meta?.name ?? key}
                      </h3>
                      <span className="text-[11.5px] text-[#65738B]">
                        {meta?.version}
                      </span>
                    </div>
                    <Badge
                      variant={
                        meta?.licence === 'identifier' ? 'warning' : 'success'
                      }
                    >
                      {meta?.licence === 'identifier'
                        ? 'identifier only'
                        : 'full text'}
                    </Badge>
                  </div>

                  <div className="mt-3 flex items-baseline gap-2">
                    <span
                      className={`text-2xl font-bold ${
                        empty ? 'text-[#8FA0BC]' : 'text-[#F5F8FF]'
                      }`}
                    >
                      {count.toLocaleString()}
                    </span>
                    <span className="text-[12px] text-[#8FA0BC]">
                      controls indexed
                    </span>
                  </div>

                  {/* An empty catalogue is explained, never left as a bare zero.
                      A zero with no reason reads as a bug or an oversight; both
                      of these are deliberate refusals to guess. */}
                  <p
                    className={`mt-2 text-[12.5px] leading-relaxed ${
                      empty ? 'text-[#F5B82E]' : 'text-[#AAB8D0]'
                    }`}
                  >
                    {empty && <strong>Intentionally unpopulated. </strong>}
                    {meta?.note}
                  </p>
                </Card>
              );
            })}
          </div>

          <div className="rounded-2xl border border-[rgba(100,150,220,0.14)] bg-[rgba(14,27,50,0.4)] p-4 text-xs leading-relaxed text-[#AAB8D0]">
            {data.note} Licence handling is enforced in the type system rather
            than by policy, so copyrighted text cannot be emitted by
            construction.
          </div>

          {/* Below the rule, and deliberately so: everything above describes
              how a DEVICE should be configured. What follows governs the AI
              inside this tool. */}
          <hr className="my-2 border-0 border-t border-[rgba(100,150,220,0.14)]" />
          <AiGovernance />
        </>
      )}
    </div>
  );
};

export default Frameworks;
