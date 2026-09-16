import type { FC } from 'react';
import { Bot, ShieldAlert } from 'lucide-react';
import { Card } from './ui/Card';
import { Badge } from './ui/Badge';
import { ErrorPanel, Loading } from './ui/States';
import { api } from '../lib/api';
import { useApi } from '../lib/useApi';

/**
 * MITRE ATLAS and the NIST AI Risk Management Framework.
 *
 * Rendered as its own section, BELOW the compliance catalogues and visually
 * separated, because it answers a different question. NIST 800-53, CIS, STIG
 * and ISO describe how a firewall should be configured. ATLAS and the AI RMF
 * describe how an AI system should be governed -- and the AI system here is
 * NCSA's own mapping suggester.
 *
 * Listing them in the same table would imply we audit firewalls against ATLAS.
 * That claim would be meaningless -- ATLAS catalogues attacks on
 * machine-learning systems, not misconfigurations on an appliance -- and it is
 * exactly the sort of thing a knowledgeable reviewer catches.
 */

/** What each AI RMF function is for, so the grouping means something. */
const FUNCTION_MEANING: Record<string, string> = {
  GOVERN: 'Policy, accountability and who may approve a change',
  MAP: 'Understanding where the AI is exposed to untrusted input',
  MEASURE: 'Detecting when the AI behaves differently than before',
  MANAGE: 'Constraining what the AI is allowed to produce',
};

const FUNCTION_ORDER = ['GOVERN', 'MAP', 'MEASURE', 'MANAGE'];

export const AiGovernance: FC = () => {
  const { data, loading, error, reload } = useApi(() => api.aiGovernance(), []);

  if (loading) return <Loading label="Loading AI governance" />;
  if (error) return <ErrorPanel error={error} onRetry={reload} />;
  if (!data) return null;

  const check = data.atlas.identifier_check;
  const allResolve =
    check !== null && check.claimed === check.resolve_in_atlas;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 pt-2">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[rgba(155,120,255,0.15)] text-[#9B78FF]">
          <Bot className="h-4 w-4" />
        </div>
        <div>
          <h2 className="text-base font-bold text-[#F5F8FF]">
            Governing our own AI
          </h2>
          <p className="text-[12px] text-[#8FA0BC]">
            MITRE ATLAS · NIST AI Risk Management Framework
          </p>
        </div>
      </div>

      {/* The scope note is not decoration. Without it a reader will assume
          these sit alongside the device catalogues above. */}
      <div className="rounded-2xl border border-[rgba(155,120,255,0.25)] bg-[rgba(155,120,255,0.06)] p-4 text-[12.5px] leading-relaxed text-[#AAB8D0]">
        <strong className="text-[#9B78FF]">Different scope.</strong>{' '}
        {data.scope}
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Card variant="panel">
          <span className="block text-xl font-bold text-[#F5F8FF]">
            {data.atlas.techniques}
          </span>
          <span className="text-[11px] text-[#8FA0BC]">
            ATLAS techniques loaded
          </span>
        </Card>
        <Card variant="panel">
          <span className="block text-xl font-bold text-[#F5F8FF]">
            {data.guardrails.length}
          </span>
          <span className="text-[11px] text-[#8FA0BC]">
            guardrails, mapped to all four AI RMF functions
          </span>
        </Card>
        <Card variant="panel">
          <span className="block text-xl font-bold text-[#F5F8FF]">
            {data.injection_signatures}
          </span>
          <span className="text-[11px] text-[#8FA0BC]">
            injection signatures, checked on every upload
          </span>
        </Card>
      </div>

      {/* The identifier check is the proof that matters: a fabricated ATLAS id
          would be worse than citing none, exactly as with STIG and CIS. */}
      {check && (
        <div className="flex flex-wrap items-center gap-2 rounded-2xl border border-[rgba(100,150,220,0.14)] bg-[rgba(14,27,50,0.4)] p-3 text-[12.5px] text-[#AAB8D0]">
          <ShieldAlert className="h-4 w-4 shrink-0 text-[#8FA0BC]" />
          <span>
            Every ATLAS identifier cited is checked against MITRE's published
            bundle:
          </span>
          <Badge variant={allResolve ? 'success' : 'critical'}>
            {check.resolve_in_atlas} of {check.claimed} resolve
          </Badge>
          <span className="text-[#65738B]">
            An invented identifier would be worse than citing none.
          </span>
        </div>
      )}

      <Card variant="default" className="overflow-hidden p-0">
        <div className="border-b border-[rgba(100,150,220,0.12)] p-4">
          <h3 className="text-sm font-bold text-[#F5F8FF]">
            Guardrails, by AI RMF function
          </h3>
          <p className="mt-0.5 text-[12px] text-[#8FA0BC]">
            Each defence, and the ATLAS technique it answers. Process controls
            carry no technique — a two-person rule constrains people, not an
            adversary's method, and inventing a mapping for it would be worse
            than leaving it blank.
          </p>
        </div>

        {FUNCTION_ORDER.filter((fn) => data.ai_rmf_functions[fn]).map((fn) => {
          const items = data.guardrails.filter((g) => g.ai_rmf === fn);
          return (
            <div
              key={fn}
              className="border-b border-[rgba(100,150,220,0.08)] p-4 last:border-0"
            >
              <div className="mb-2 flex flex-wrap items-baseline gap-2">
                <Badge variant="info">{fn}</Badge>
                <span className="text-[12px] text-[#8FA0BC]">
                  {FUNCTION_MEANING[fn]}
                </span>
              </div>
              <div className="space-y-1.5">
                {items.map((g) => (
                  <div
                    key={g.guardrail}
                    className="flex flex-wrap items-baseline gap-x-2 gap-y-1 text-[12.5px]"
                  >
                    <span className="text-[#F5F8FF]">{g.guardrail}</span>
                    {g.atlas.length > 0 ? (
                      g.atlas.map((t) => (
                        <span
                          key={t}
                          className="rounded-full border border-[rgba(100,150,220,0.2)] px-2 py-0.5 font-mono text-[10.5px] text-[#AAB8D0]"
                        >
                          {t}
                        </span>
                      ))
                    ) : (
                      <span className="text-[11px] italic text-[#65738B]">
                        process control — no attack technique
                      </span>
                    )}
                    <span className="text-[11px] text-[#65738B]">
                      {g.owasp_llm}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </Card>

      <div className="rounded-2xl border border-[rgba(100,150,220,0.14)] bg-[rgba(14,27,50,0.4)] p-4 text-[12px] leading-relaxed text-[#AAB8D0]">
        <strong className="text-[#F5F8FF]">Corpus isolation.</strong>{' '}
        {data.corpus_isolation}
      </div>
    </div>
  );
};
