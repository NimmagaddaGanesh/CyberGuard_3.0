'use client';

import { useState } from 'react';
import { PRESET_ALERTS, ATTACK_CATEGORIES } from '@/lib/mockData';
import {
  investigateAlert,
  submitFeedback,
} from '@/lib/api';
import { InvestigationResult, Alert } from '@/types/cyberguard';

export default function Home() {
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [loading, setLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState<string>('');
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [feedbackSubmitted, setFeedbackSubmitted] = useState(false);
  const [feedbackOutcome, setFeedbackOutcome] = useState<'success' | 'failed' | null>(null);
  
  // Escalation & Deep Security State
  const [escalationCount, setEscalationCount] = useState<number>(0);
  const [isExhausted, setIsExhausted] = useState<boolean>(false);
  const [deepMemo, setDeepMemo] = useState<string | null>(null);
  const [emergencyActions, setEmergencyActions] = useState<string[]>([]);
  const [warRoomDispatched, setWarRoomDispatched] = useState<boolean>(false);
  
  const [alternatePlaybookInfo, setAlternatePlaybookInfo] = useState<{
    alternate_playbook?: string;
    alternate_steps?: string[];
    escalation_tier?: string;
  } | null>(null);

  const [selectedAttack, setSelectedAttack] = useState<string>('SSH Brute Force');
  const [rawInput, setRawInput] = useState('');

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  const runPipeline = async (
    rawInputData: Alert | string,
    source: 'PRESET_SELECTION' | 'RAW_SYSLOG_WEBHOOK'
  ) => {
    setLoading(true);
    setFeedbackSubmitted(false);
    setFeedbackOutcome(null);
    setAlternatePlaybookInfo(null);
    setEscalationCount(0);
    setIsExhausted(false);
    setDeepMemo(null);
    setEmergencyActions([]);
    setWarRoomDispatched(false);
    setLoadingStep('Ingesting threat telemetry and evaluating playbook...');

    try {
      const data = await investigateAlert(rawInputData, source);
      setResult(data);
    } catch (err) {
      console.error('Telemetry processing error:', err);
    } finally {
      setLoading(false);
      setLoadingStep('');
    }
  };

  const handleDropdownSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAttack) return;
    const alertData = PRESET_ALERTS[selectedAttack];
    if (alertData) {
      runPipeline(alertData, 'PRESET_SELECTION');
    }
  };

  const handleRawInputSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!rawInput.trim()) return;
    runPipeline(rawInput, 'RAW_SYSLOG_WEBHOOK');
  };

  const handleFeedback = async (outcome: 'success' | 'failed') => {
    if (!result) return;

    const nextCount = outcome === 'failed' ? escalationCount + 1 : escalationCount;
    const incidentId = 'INC-2026-0042';
    const resolutionId = result.recommendation.resolution_id;

    try {
      const res = await submitFeedback({
        incident_id: incidentId,
        resolution_id: resolutionId,
        outcome,
        escalation_count: nextCount,
      });

      if (res.memory_updated) {
        setFeedbackSubmitted(true);
        setFeedbackOutcome(outcome);
        setEscalationCount(nextCount);

        if (outcome === 'failed') {
          if (nextCount >= 2 || res.is_exhausted) {
            // Level 2 Escalation Ceiling Reached: Groq LLM Deep Security Memo
            setIsExhausted(true);
            setDeepMemo(res.deep_investigation_memo || null);
            setEmergencyActions(res.emergency_actions || []);
          } else {
            // Level 1: Tier-2 Alternate Playbook
            setAlternatePlaybookInfo({
              alternate_playbook: res.alternate_playbook || result.recommendation.alternate_playbook,
              alternate_steps: res.alternate_steps && res.alternate_steps.length > 0 
                ? res.alternate_steps 
                : result.recommendation.alternate_steps,
              escalation_tier: res.escalation_tier || result.recommendation.escalation_tier,
            });
          }
        }

        setResult((prev) =>
          prev
            ? {
                ...prev,
                recommendation: {
                  ...prev.recommendation,
                  times_used: res.metrics.times_used,
                  success_rate: res.metrics.success_rate,
                  successful_resolutions: res.metrics.successful_resolutions,
                },
              }
            : null
        );
      }
    } catch (err) {
      console.error('Feedback submission error:', err);
    }
  };

  return (
    <div className={theme}>
      <main className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 p-8 font-sans transition-colors duration-200">
        <header className="mb-8 border-b border-slate-200 dark:border-slate-800 pb-4 flex justify-between items-center">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-2">
              CYBERGUARD <span className="text-xs px-2 py-0.5 rounded bg-purple-100 dark:bg-purple-950 text-purple-700 dark:text-purple-300 font-mono font-normal">v2.4 Enterprise</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">
              Autonomous Threat Detection, Hindsight Memory & Adaptive Playbook Orchestration
            </p>
          </div>

          <div className="flex items-center gap-4 text-xs font-mono">
            {loading ? (
              <span className="text-amber-500 dark:text-amber-400 font-semibold flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-amber-500 animate-ping"></span>
                ANALYZING TELEMETRY...
              </span>
            ) : (
              <span className="text-emerald-600 dark:text-emerald-400 font-semibold flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-emerald-500"></span>
                AGENT ENGINE ACTIVE
              </span>
            )}
            <button
              onClick={toggleTheme}
              className="px-3 py-1 bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 rounded transition cursor-pointer text-slate-800 dark:text-slate-200 font-sans"
            >
              {theme === 'dark' ? '☀️ Light' : '🌙 Dark'}
            </button>
          </div>
        </header>

        <section className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg shadow-sm">
            <h2 className="text-xs font-mono text-slate-500 dark:text-slate-400 uppercase mb-2 font-semibold">
              Select Threat Scenario (18 Pre-Configured Playbooks)
            </h2>
            <div className="flex flex-col gap-2">
              <form onSubmit={handleDropdownSubmit}>
                <select
                  value={selectedAttack}
                  onChange={(e) => setSelectedAttack(e.target.value)}
                  className="w-full p-2 bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-800 rounded text-xs font-mono text-slate-900 dark:text-slate-200 focus:outline-none focus:border-purple-500"
                >
                  <optgroup label="🛡️ Traditional Enterprise Threats">
                    {ATTACK_CATEGORIES.TRADITIONAL.map((attack) => (
                      <option key={attack} value={attack}>
                        {attack}
                      </option>
                    ))}
                  </optgroup>
                  <optgroup label="🤖 AI & LLM Infrastructure Threats">
                    {ATTACK_CATEGORIES.AI_SECURITY.map((attack) => (
                      <option key={attack} value={attack}>
                        {attack}
                      </option>
                    ))}
                  </optgroup>
                </select>
                <button
                  type="submit"
                  className="mt-2 w-full py-2 bg-purple-600 hover:bg-purple-500 text-white rounded text-xs font-semibold cursor-pointer transition"
                >
                  Execute Incident Analysis
                </button>
              </form>
            </div>
          </div>

          <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg shadow-sm">
            <h2 className="text-xs font-mono text-slate-500 dark:text-slate-400 uppercase mb-2 font-semibold">
              Telemetry & Syslog Ingestion
            </h2>
            <form onSubmit={handleRawInputSubmit} className="flex flex-col gap-2">
              <textarea
                rows={4}
                value={rawInput}
                onChange={(e) => setRawInput(e.target.value)}
                placeholder="Paste raw syslog stream, SIEM alert, or AI agent tool log..."
                className="w-full p-2 bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-800 rounded text-xs font-mono text-slate-900 dark:text-slate-200 focus:outline-none focus:border-purple-500"
              />
              <button
                type="submit"
                className="self-end px-4 py-1.5 bg-slate-800 dark:bg-slate-700 hover:bg-slate-700 dark:hover:bg-slate-600 text-white rounded text-xs font-semibold cursor-pointer transition"
              >
                Ingest Raw Payload
              </button>
            </form>
          </div>
        </section>

        {loading && (
          <div className="p-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg font-mono text-sm text-purple-600 dark:text-purple-400 animate-pulse shadow-sm">
            <p className="text-xs text-slate-400 dark:text-slate-500 mb-1">
              AUTOMATED INVESTIGATION IN PROGRESS
            </p>
            <p className="font-bold">{loadingStep}</p>
          </div>
        )}

        {!loading && result && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg shadow-sm">
              <div className="flex justify-between items-start mb-4">
                <div>
                  <span className="text-xs font-mono text-purple-600 dark:text-purple-400 uppercase font-semibold">
                    Recommended Playbook ({result.recommendation.resolution_id})
                  </span>
                  <h2 className="text-xl font-bold text-slate-900 dark:text-white mt-1">
                    {result.recommendation.resolution}
                  </h2>
                  <p className="text-xs font-mono text-slate-500 mt-1">
                    Domain: <span className="text-slate-700 dark:text-slate-300">{result.recommendation.response_domain}</span> | Priority: <span className="text-rose-500 font-semibold">{result.recommendation.priority}</span>
                  </p>
                </div>
                <span className="px-2.5 py-1 text-xs font-mono bg-purple-100 dark:bg-purple-950 text-purple-700 dark:text-purple-300 border border-purple-300 dark:border-purple-800 rounded">
                  Confidence: {(result.recommendation.confidence * 100).toFixed(0)}%
                </span>
              </div>

              {/* Metrics Grid */}
              <div className="grid grid-cols-3 gap-4 my-4 p-4 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800 text-center">
                <div>
                  <p className="text-xs text-slate-500 font-mono">Success Rate</p>
                  <p className="text-lg font-bold text-emerald-600 dark:text-emerald-400">
                    {(result.recommendation.success_rate * 100).toFixed(1)}%
                  </p>
                </div>
                <div>
                  <p className="text-xs text-slate-500 font-mono">Times Deployed</p>
                  <p className="text-lg font-bold text-slate-900 dark:text-white">
                    {result.recommendation.times_used}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-slate-500 font-mono">Successful</p>
                  <p className="text-lg font-bold text-slate-900 dark:text-white">
                    {result.recommendation.successful_resolutions}
                  </p>
                </div>
              </div>

              {/* Contingency Preview (If Level 0) */}
              {!alternatePlaybookInfo && !isExhausted && result.recommendation.alternate_playbook && (
                <div className="my-3 p-3 bg-purple-50/60 dark:bg-purple-950/30 rounded border border-purple-200 dark:border-purple-900 text-xs">
                  <span className="font-mono text-purple-700 dark:text-purple-300 font-semibold uppercase">
                    Contingency Alternate Playbook (Tier-2):
                  </span>
                  <p className="text-slate-700 dark:text-slate-300 mt-1">
                    {result.recommendation.alternate_playbook}
                  </p>
                  <p className="text-[10px] font-mono text-purple-600 dark:text-purple-400 mt-1">
                    Escalation Route: {result.recommendation.escalation_tier || 'Tier-2 DFIR'}
                  </p>
                </div>
              )}

              {/* Level 1: Tier-2 Alternate Playbook Deployed */}
              {alternatePlaybookInfo && !isExhausted && (
                <div className="my-4 p-4 bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono font-bold text-amber-700 dark:text-amber-300 uppercase flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-full bg-amber-500 animate-ping"></span>
                      ⚠️ ESCALATION LEVEL 1: Tier-2 Alternate Playbook Deployed
                    </span>
                    <span className="text-[10px] font-mono bg-amber-200 dark:bg-amber-900 text-amber-800 dark:text-amber-200 px-2 py-0.5 rounded">
                      {alternatePlaybookInfo.escalation_tier || 'Tier-2 DFIR'}
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-2">
                    {alternatePlaybookInfo.alternate_playbook}
                  </h3>
                  {alternatePlaybookInfo.alternate_steps && alternatePlaybookInfo.alternate_steps.length > 0 && (
                    <div className="mt-2">
                      <p className="text-[11px] font-mono text-amber-700 dark:text-amber-300 font-semibold mb-1">
                        Advanced Containment Steps:
                      </p>
                      <ol className="list-decimal list-inside space-y-1 text-xs text-slate-700 dark:text-slate-300">
                        {alternatePlaybookInfo.alternate_steps.map((step, idx) => (
                          <li key={idx} className="leading-relaxed py-0.5">{step}</li>
                        ))}
                      </ol>
                    </div>
                  )}
                  <div className="mt-3 pt-2 border-t border-amber-200 dark:border-amber-900 text-[11px] text-amber-700 dark:text-amber-300 font-mono">
                    ✓ Tier-1 failure recorded in Hindsight Cloud.
                  </div>
                </div>
              )}

              {/* Level 2 (CEILING REACHED): Groq LLM Deep Security Crisis Dossier */}
              {isExhausted && (
                <div className="my-4 p-4 bg-rose-50 dark:bg-rose-950/50 border-2 border-rose-500 rounded-lg shadow-lg">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono font-bold text-rose-700 dark:text-rose-300 uppercase flex items-center gap-1.5">
                      <span className="h-2.5 w-2.5 rounded-full bg-rose-600 animate-ping"></span>
                      🚨 ESCALATION LIMIT REACHED: NO AUTOMATED SOLUTION FOUND
                    </span>
                    <span className="text-[10px] font-mono bg-rose-600 text-white font-bold px-2 py-0.5 rounded">
                      SEV-0 / WAR ROOM
                    </span>
                  </div>
                  <p className="text-xs text-rose-900 dark:text-rose-200 mb-3 font-semibold">
                    Both Tier-1 and Tier-2 automated playbooks failed to neutralize this threat. Automated execution has been frozen to prevent denial-of-service and preserve volatile evidence. Transferred to Deep Security & DFIR Investigation.
                  </p>

                  {/* Groq LLM Executive Triage Memo */}
                  {deepMemo && (
                    <div className="my-3 p-3 bg-white dark:bg-slate-900 rounded border border-rose-300 dark:border-rose-800 text-xs text-slate-800 dark:text-slate-200 leading-relaxed font-sans">
                      <p className="text-[11px] font-mono text-purple-600 dark:text-purple-400 font-bold mb-1 flex items-center gap-1">
                        <span>🤖</span> GROQ LLM PRINCIPAL INCIDENT COMMANDER DIRECTIVE:
                      </p>
                      <p className="italic">{deepMemo}</p>
                    </div>
                  )}

                  {/* Mandatory Emergency Directives */}
                  {emergencyActions && emergencyActions.length > 0 && (
                    <div className="mt-3">
                      <p className="text-[11px] font-mono text-rose-700 dark:text-rose-300 font-bold uppercase mb-1">
                        Mandatory Emergency Actions Required:
                      </p>
                      <ul className="list-disc list-inside space-y-1 text-xs text-slate-800 dark:text-slate-200">
                        {emergencyActions.map((act, idx) => (
                          <li key={idx} className="leading-relaxed py-0.5">{act}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Dispatch War Room Action */}
                  <div className="mt-4 pt-3 border-t border-rose-200 dark:border-rose-900 flex justify-between items-center">
                    {!warRoomDispatched ? (
                      <button
                        onClick={() => setWarRoomDispatched(true)}
                        className="w-full py-2 bg-rose-600 hover:bg-rose-500 text-white rounded text-xs font-mono font-bold tracking-wider uppercase transition cursor-pointer shadow-md"
                      >
                        [ 📞 DISPATCH SEV-0 WAR ROOM & PAGE ON-CALL CISO ]
                      </button>
                    ) : (
                      <div className="w-full p-2 bg-rose-100 dark:bg-rose-900/60 text-rose-800 dark:text-rose-200 text-xs font-mono font-semibold text-center rounded border border-rose-400">
                        ✓ PagerDuty SEV-0 Alert Broadcasted. Principal DFIR Commander & CISO Notified.
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Action Buttons depending on Level */}
              {!isExhausted && (
                <div className="mt-6 border-t border-slate-200 dark:border-slate-800 pt-4">
                  {feedbackOutcome === 'success' ? (
                    <div className="p-4 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-300 dark:border-emerald-800 rounded-lg text-center">
                      <div className="flex items-center justify-center gap-2 text-emerald-700 dark:text-emerald-300 font-bold text-sm mb-1">
                        <span>✓</span> INCIDENT SUCCESSFULLY RESOLVED
                      </div>
                      <p className="text-xs text-emerald-800 dark:text-emerald-200 font-mono">
                        Playbook mitigation verified by SOC Analyst. Empirical weights updated and retained in Hindsight Cloud.
                      </p>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-2 font-mono">
                        🔒 Escalation locked: Threat has been successfully neutralized.
                      </p>
                    </div>
                  ) : (
                    <>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mb-3 font-mono">
                        {escalationCount === 0 
                          ? 'Analyst Incident Resolution Outcome (Tier-1)' 
                          : 'Tier-2 Alternate Playbook Resolution Outcome'}
                      </p>
                      
                      {escalationCount === 0 ? (
                        // Initial Level 0 Buttons
                        <div className="flex gap-3">
                          <button
                            onClick={() => handleFeedback('success')}
                            className="flex-1 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-sm font-semibold transition cursor-pointer"
                          >
                            [ ✓ RESOLVED ]
                          </button>
                          <button
                            onClick={() => handleFeedback('failed')}
                            className="flex-1 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded text-sm font-semibold transition cursor-pointer"
                          >
                            [ ✕ ESCALATE ]
                          </button>
                        </div>
                      ) : (
                        // Level 1 Buttons: Mark Alternate Resolved OR Escalate to Tier-3 Deep Security
                        <div className="flex flex-col gap-2">
                          <button
                            onClick={() => handleFeedback('success')}
                            className="w-full py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-sm font-semibold transition cursor-pointer"
                          >
                            [ ✓ Mark Alternate Playbook Resolved ]
                          </button>
                          <button
                            onClick={() => handleFeedback('failed')}
                            className="w-full py-2 bg-rose-600 hover:bg-rose-500 text-white rounded text-xs font-mono font-bold uppercase transition cursor-pointer"
                          >
                            [ 🚨 Alternate Failed — Escalate to Deep Security (Tier-3) ]
                          </button>
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}
            </div>

            {/* Historical Matches Intelligence */}
            <div className="p-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg shadow-sm">
              <h3 className="text-xs font-mono text-slate-500 dark:text-slate-400 uppercase mb-4 font-semibold">
                Historical Incident Intelligence (Hindsight Bank: cyberguard-soc)
              </h3>
              {result.historical_matches.length === 0 ? (
                <p className="text-sm text-slate-500 font-mono">
                  No prior similar incidents recorded in knowledge base.
                </p>
              ) : (
                <ul className="space-y-3">
                  {result.historical_matches.map((match, index) => (
                    <li
                      key={`${match.incident_id}-${match.resolution}-${index}`}
                      className="p-3 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800 text-sm"
                    >
                      <div className="flex justify-between items-center mb-1">
                        <span className="font-mono text-purple-600 dark:text-purple-400 text-xs font-semibold">
                          {match.incident_id}
                        </span>
                        <span className="text-xs font-mono text-emerald-600 dark:text-emerald-400 font-semibold">
                          {(match.similarity * 100).toFixed(0)}% Similarity
                        </span>
                      </div>
                      <p className="text-slate-700 dark:text-slate-300">{match.resolution}</p>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
