import { useState, type FC } from 'react';
import { FileDown, History } from 'lucide-react';

import { Card } from '../ui/Card';
import { api, type HistoryPoint } from '../../lib/api';
import { useApi } from '../../lib/useApi';

const FRAMEWORKS: [string, string][] = [
  ['nist_800_53', 'NIST'],
  ['iso_27001', 'ISO 27001'],
  ['stig', 'STIG'],
  ['cis', 'CIS'],
];

const pct = (v: number | null | undefined) => (v === null || v === undefined ? '—' : `${v}%`);

/**
 * The formal report -- whole, or scoped to one framework -- and the device's
 * framework scores over time. Snapshots are recorded only when asked for:
 * viewing history never writes one.
 */
const ReportAndHistory: FC<{ aid: string }> = ({ aid }) => {
  const { data: points, reload } = useApi<HistoryPoint[]>(() => api.history(aid), [aid]);
  const [saving, setSaving] = useState(false);

  const record = async () => {
    setSaving(true);
    try {
      await api.recordSnapshot(aid);
      reload();
    } finally {
      setSaving(false);
    }
  };

  const link =
    'inline-flex items-center gap-1.5 rounded-full border border-[rgba(100,150,220,0.25)] px-3 py-1.5 text-xs font-semibold text-[#DDE7F7] hover:border-[#1677FF]';

  return (
    <Card variant="default" className="p-6 space-y-5">
      <div>
        <h3 className="flex items-center gap-2 text-sm font-bold text-[#F5F8FF]">
          <FileDown className="h-4 w-4 text-[#2D8CFF]" /> Assessment report
        </h3>
        <div className="mt-3 flex flex-wrap gap-2">
          <a className={link} href={api.reportUrl(aid)}>
            PDF — all frameworks
          </a>
          {FRAMEWORKS.map(([key, label]) => (
            <a key={key} className={link} href={api.reportUrl(aid, key)}>
              PDF — {label} only
            </a>
          ))}
        </div>
        <p className="mt-2 text-[11.5px] text-[#8FA0BC]">
          A single-framework report re-assesses the same configuration with only
          that framework selected, so it always matches a scoped assessment.
        </p>
      </div>

      <div className="border-t border-[rgba(100,150,220,0.12)] pt-4">
        <div className="flex items-center justify-between gap-3">
          <h3 className="flex items-center gap-2 text-sm font-bold text-[#F5F8FF]">
            <History className="h-4 w-4 text-[#2D8CFF]" /> Framework scores over time
          </h3>
          <button onClick={record} disabled={saving} className={link}>
            {saving ? 'Recording…' : 'Record snapshot'}
          </button>
        </div>
        {points && points.length > 0 ? (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left text-[12.5px]">
              <thead className="text-[10.5px] uppercase tracking-wider text-[#65738B]">
                <tr>
                  <th className="py-1 pr-4">Taken</th>
                  <th className="py-1 pr-4 text-right">Overall</th>
                  {FRAMEWORKS.map(([key, label]) => (
                    <th key={key} className="py-1 pr-4 text-right">{label}</th>
                  ))}
                  <th className="py-1 text-right">Config</th>
                </tr>
              </thead>
              <tbody className="text-[#DDE7F7]">
                {points.map((p) => (
                  <tr key={p.taken_at} className="border-t border-[rgba(100,150,220,0.1)]">
                    <td className="py-1.5 pr-4 font-mono text-[11.5px]">{p.taken_at}</td>
                    <td className="py-1.5 pr-4 text-right">{pct(p.score_pct)}</td>
                    {FRAMEWORKS.map(([key]) => (
                      <td key={key} className="py-1.5 pr-4 text-right">
                        {pct(p.frameworks?.[key])}
                      </td>
                    ))}
                    <td className="py-1.5 text-right font-mono text-[11px] text-[#8FA0BC]">
                      {p.config_sha256}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="mt-2 text-[11.5px] text-[#8FA0BC]">
            No snapshots of this device yet. Record one now and again after a
            change to see each framework's score move.
          </p>
        )}
      </div>
    </Card>
  );
};

export default ReportAndHistory;
