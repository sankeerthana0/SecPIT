import React, { useState } from "react";
import { AlertEntry, LogEntry, AIAnalysisResult } from "../types";
import { 
  ShieldAlert, 
  ShieldX, 
  Sparkles, 
  Terminal, 
  CheckCircle2, 
  XOctagon, 
  AlertOctagon,
  Copy, 
  Check, 
  LifeBuoy, 
  BookOpen, 
  Cpu
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";

interface AlertsTabProps {
  alerts: AlertEntry[];
  logs: LogEntry[];
  onAcknowledgeAlert: (id: string) => void;
  onBlockIp: (id: string, ip: string) => void;
  onSetAiAnalysis: (alertId: string, info: AIAnalysisResult) => void;
  blacklistedIps: Set<string>;
}

export default function AlertsTab({
  alerts,
  logs,
  onAcknowledgeAlert,
  onBlockIp,
  onSetAiAnalysis,
  blacklistedIps
}: AlertsTabProps) {
  const [selectedAlert, setSelectedAlert] = useState<AlertEntry | null>(alerts[0] || null);
  const [copiedState, setCopiedState] = useState(false);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  // Filter alerts currently in session
  const unresolvedAlerts = alerts.filter(a => a.status === "Unresolved");
  const resolvedAlerts = alerts.filter(a => a.status !== "Unresolved");

  const handleCopyScript = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedState(true);
    setTimeout(() => setCopiedState(false), 2000);
  };

  const handleRequestAiAnalysis = async (alert: AlertEntry) => {
    setIsAiLoading(true);
    setAiError(null);

    // Filter logs with same IP to send as supportive context
    const correlativeLogs = logs.filter(l => l.sourceIp === alert.sourceIp).slice(0, 8);

    try {
      const res = await fetch("/api/analyze-threat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alert, correlativeLogs })
      });

      if (!res.ok) {
        throw new Error("Target Express service returned error. Failsafe activated.");
      }

      const report: AIAnalysisResult = await res.json();
      
      onSetAiAnalysis(alert.id, report);
      
      // Update selected alert local state representation
      setSelectedAlert(prev => prev ? { ...prev, aiAnalysis: report } : null);
    } catch (err: any) {
      console.error(err);
      setAiError(err.message || "Failed to finalize AI SOC report.");
    } finally {
      setIsAiLoading(false);
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6" id="alerts_tab_root">
      
      {/* COLUMN 1: ALERTS INBOX (COL 1 to 5) */}
      <div className="lg:col-span-5 space-y-6">
        <div className="bg-[#0D0D0D] border border-[#222] rounded-none p-5 flex flex-col h-[580px]">
          <div className="flex items-center gap-2 mb-4 border-b border-[#222] pb-3.5 select-none">
            <ShieldAlert className="h-5 w-5 text-[#FF2E2E] animate-pulse" />
            <div>
              <h3 className="text-sm font-black text-white font-display uppercase tracking-wider italic">Security Alerts Inbox</h3>
              <p className="text-[11px] text-slate-550 font-mono mt-0.5">{unresolvedAlerts.length} unresolved threat patterns flagging</p>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto space-y-2.5 pr-1">
            {alerts.length === 0 ? (
              <div className="text-center py-20 text-slate-650 font-mono text-xs">
                <CheckCircle2 className="h-8 w-8 text-emerald-500 mx-auto mb-2.5" />
                No threat patterns matched. Signature engines report standard baseline.
              </div>
            ) : (
              alerts.map((alert) => {
                const isActive = selectedAlert?.id === alert.id;
                const isIpBlacklisted = blacklistedIps.has(alert.sourceIp);

                return (
                  <div 
                    key={alert.id}
                    onClick={() => {
                      setSelectedAlert(alert);
                      setAiError(null);
                    }}
                    className={`p-3.5 rounded-none border text-left cursor-pointer transition flex gap-3 ${
                      isActive 
                        ? "bg-[#111111] border-[#00F0FF]" 
                        : alert.status === "Blocked"
                          ? "bg-[#0b1b11]/30 border-emerald-950/40 text-emerald-400"
                          : "bg-[#050505] border-[#222]/65 hover:bg-[#111]"
                    }`}
                  >
                    <div className="pt-0.5">
                      {alert.severity === "Critical" ? (
                        <XOctagon className="h-5 w-5 text-[#FF2E2E] shrink-0" />
                      ) : alert.severity === "High" ? (
                        <AlertOctagon className="h-5 w-5 text-[#FF2E2E]/80 shrink-0" />
                      ) : (
                        <ShieldAlert className="h-5 w-5 text-amber-500 shrink-0" />
                      )}
                    </div>

                    <div className="flex-1 space-y-1 overflow-hidden">
                      <div className="flex justify-between items-center text-[9px] text-slate-500 font-mono uppercase tracking-wider">
                        <span>{new Date(alert.timestamp).toLocaleTimeString()}</span>
                        <span className={`px-1.5 py-0.2 rounded-none font-black border ${
                          alert.severity === "Critical" 
                            ? "bg-[#251011] border-[#FF2E2E]/40 text-[#FF2E2E]" 
                            : alert.severity === "High" 
                              ? "bg-[#251011] border-[#FF2E2E]/20 text-[#FF2E2E]/80" 
                              : "bg-[#1d120a] border-amber-900/30 text-amber-500"
                        }`}>
                          {alert.severity}
                        </span>
                      </div>

                      <div className="font-mono font-black text-xs text-white uppercase truncate tracking-wide">{alert.ruleName.replace(/_/g, " ")}</div>
                      <div className="text-[11px] text-slate-400 font-mono truncate">IP: <span className="text-[#00F0FF] font-black">{alert.sourceIp}</span> | Port: {alert.targetPort}</div>
                      
                      <div className="flex items-center gap-1.5 pt-1 text-[9px] font-bold uppercase tracking-wider font-mono">
                        {alert.status === "Blocked" ? (
                          <span className="text-emerald-400 bg-[#0b1b11] px-1.5 py-0.5 border border-emerald-900/30">CONTAINED</span>
                        ) : isIpBlacklisted ? (
                          <span className="text-amber-500 bg-[#1d120a] px-1.5 py-0.5 border border-amber-900/30">BANNED LATENT</span>
                        ) : (
                          <span className="text-[#FF2E2E] bg-[#251011] px-1.5 py-0.5 border border-[#FF2E2E]/25">THREAT ACTIVE</span>
                        )}
                        <span className="text-slate-700">·</span>
                        <span className="text-slate-500">{alert.engine}</span>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* COLUMN 2: INVESTIGATION DESK (COL 6 to 12) */}
      <div className="lg:col-span-7 space-y-6">
        <div className="bg-[#0D0D0D] border border-[#222] rounded-none p-6 flex flex-col min-h-[580px]">
          
          {!selectedAlert ? (
            <div className="flex-1 flex flex-col items-center justify-center text-center py-20 text-slate-655 font-mono text-xs">
              <LifeBuoy className="h-10 w-10 text-neutral-800 mb-2.5 animate-bounce" />
              Analyze threat events or trigger active response procedures. Choose an alert profile.
            </div>
          ) : (
            <div className="flex-1 flex flex-col">
              
              {/* Alert Title Header and Immediate Action Deck */}
              <div className="pb-4 border-b border-[#222] flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <div>
                  <span className="text-[9px] font-mono text-slate-500 tracking-wider">ALRT_UUID: {selectedAlert.id}</span>
                  <h3 className="text-sm font-black text-white font-mono uppercase tracking-wide">{selectedAlert.ruleName.replace(/_/g, " ")}</h3>
                </div>

                <div className="flex gap-2 text-xs font-mono font-bold">
                  {selectedAlert.status !== "Blocked" && !blacklistedIps.has(selectedAlert.sourceIp) && (
                    <button 
                      onClick={() => onBlockIp(selectedAlert.id, selectedAlert.sourceIp)}
                      className="bg-[#FF2E2E] hover:bg-rose-500 font-extrabold uppercase text-slate-950 px-4 py-2 rounded-none transition duration-150 cursor-pointer"
                    >
                      Ban Offending IP
                    </button>
                  )}

                  {selectedAlert.status === "Unresolved" && (
                    <button 
                      onClick={() => onAcknowledgeAlert(selectedAlert.id)}
                      className="bg-[#0D0D0D] border border-[#444] hover:bg-neutral-900 font-bold px-4 py-2 rounded-none text-white transition duration-150 cursor-pointer"
                    >
                      Declare Mitigated
                    </button>
                  )}
                </div>
              </div>

              {/* Alert Forensic Metrics */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 py-4 border-b border-[#222] text-xs font-mono">
                <div>
                  <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-widest">Threat IP</span>
                  <span className="text-white font-extrabold select-all">{selectedAlert.sourceIp}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-widest">Target Port</span>
                  <span className="text-slate-300 select-all">{selectedAlert.targetPort} / TCP</span>
                </div>
                <div>
                  <span className="text-slate-550 block text-[9px] uppercase font-bold tracking-widest">Trigger Engine</span>
                  <span className="text-[#00F0FF] font-bold select-all">{selectedAlert.engine}</span>
                </div>
                <div>
                  <span className="text-slate-550 block text-[9px] uppercase font-bold tracking-widest">State Indices</span>
                  <span className={`font-black select-all ${
                    selectedAlert.status === "Blocked" 
                      ? "text-emerald-400" 
                      : blacklistedIps.has(selectedAlert.sourceIp)
                        ? "text-amber-500"
                        : "text-[#FF2E2E]"
                  }`}>
                    {selectedAlert.status === "Blocked" 
                      ? "BANNED" 
                      : blacklistedIps.has(selectedAlert.sourceIp)
                        ? "BANNED LATENT"
                        : "ACTIVE PROBE"}
                  </span>
                </div>
              </div>

              {/* Alert Payload Details */}
              <div className="py-4 space-y-1.5 font-mono text-xs">
                <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-widest">Alert Message context</span>
                <p className="text-slate-300 bg-[#050505] p-3.5 rounded-none border border-[#222] text-[11px] leading-relaxed">{selectedAlert.message}</p>

                {selectedAlert.payload && (
                  <div className="pt-2">
                    <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-widest text-[#FF2E2E]">Signature match telemetry</span>
                    <pre className="bg-[#050505] border border-[#222] p-3.5 rounded-none text-[11px] overflow-x-auto break-all select-all font-mono text-[#FF2E2E] leading-relaxed">
                      {selectedAlert.payload}
                    </pre>
                  </div>
                )}
              </div>

              {/* AI SECURITY COPILOT INTEGRATION PANEL */}
              <div className="mt-4 bg-[#050505]/40 rounded-none p-5 border border-[#222] flex-1 flex flex-col">
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-4 border-b border-[#222] pb-3.5 select-none">
                  <div className="flex items-center gap-1.5">
                    <Sparkles className="h-4.5 w-4.5 text-[#00F0FF] animate-pulse" />
                    <h4 className="text-xs font-black text-white uppercase tracking-wider font-display italic">Threat Intelligence Copilot (Gemini SOC Advisor)</h4>
                  </div>
                  
                  {!selectedAlert.aiAnalysis && !isAiLoading && (
                    <button
                      onClick={() => handleRequestAiAnalysis(selectedAlert)}
                      className="bg-[#00F0FF] hover:bg-cyan-400 text-slate-950 text-[10px] uppercase font-bold px-3 py-1.5 rounded-none flex items-center gap-1.5 transition-all font-mono tracking-wider cursor-pointer font-black border-none"
                    >
                      <Sparkles className="h-3.5 w-3.5" />
                      Run Intel Audit
                    </button>
                  )}
                </div>

                {isAiLoading && (
                  <div className="flex-1 flex flex-col items-center justify-center text-center py-10 text-xs text-slate-500 font-mono">
                    <div className="animate-spin rounded-none h-6 w-6 border-2 border-[#222] border-t-[#00F0FF] mb-3"></div>
                    <span className="font-extrabold text-[#00F0FF] animate-pulse uppercase tracking-widest text-[10px]">Processing model metrics...</span>
                    <span className="text-[10px] text-slate-600 mt-2 max-w-sm leading-relaxed">Synthesizing log datasets against CVE vector repositories through deep Gemini analysis.</span>
                  </div>
                )}

                {aiError && (
                  <div className="p-3 bg-[#251011] border border-[#FF2E2E]/25 text-[#FF2E2E] rounded-none text-xs text-center font-mono">
                    {aiError}. Click run again to reinitialize failsafe telemetry.
                  </div>
                )}

                {selectedAlert.aiAnalysis && !isAiLoading && (
                  <div className="text-xs space-y-4">
                    {/* Executive Summary */}
                    <div>
                      <div className="flex items-center gap-1 text-[9px] uppercase font-bold text-[#00F0FF] tracking-wider font-mono">
                        <BookOpen className="h-3 w-3 text-slate-500" />
                        Executive Intelligence Summary
                      </div>
                      <p className="text-slate-300 mt-1 leading-relaxed text-[11px] font-mono">
                        {selectedAlert.aiAnalysis.summary}
                      </p>
                    </div>

                    {/* Threat Actor & Intent */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 border-t border-[#222] pt-3">
                      <div>
                        <div className="text-[9px] uppercase font-bold text-slate-500 tracking-wider font-mono">Estimated Threat Profile</div>
                        <p className="text-slate-350 mt-1 font-mono text-[11px] leading-relaxed">
                          {selectedAlert.aiAnalysis.threatActorProfile}
                        </p>
                      </div>
                      <div>
                        <div className="text-[9px] uppercase font-bold text-slate-500 tracking-wider font-mono">Malicious Intent</div>
                        <p className="text-slate-350 mt-1 font-mono text-[11px] leading-relaxed">
                          {selectedAlert.aiAnalysis.maliciousIntent}
                        </p>
                      </div>
                    </div>

                    {/* Criticality Explain */}
                    <div className="border-t border-[#222] pt-3">
                      <div className="text-[9px] uppercase font-bold text-slate-500 tracking-wider font-mono">Risk Index Assessment</div>
                      <p className="text-slate-350 mt-1 leading-relaxed text-[11px] font-mono">
                        {selectedAlert.aiAnalysis.criticalityExplanation}
                      </p>
                    </div>

                    {/* Actionable Containment Guidelines */}
                    <div className="border-t border-[#222] pt-3">
                      <div className="text-[9px] uppercase font-[#00F0FF] font-bold text-[#00F0FF] tracking-wider mb-2 font-mono">Containment protocol steps</div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        {selectedAlert.aiAnalysis.mitigationActions.map((action, id) => (
                          <div key={id} className="bg-[#050505] p-2.5 rounded-none border border-[#222] flex items-start gap-2 text-[10px] font-mono">
                            <span className="h-5 w-5 bg-neutral-900 border border-[#333] text-slate-400 flex items-center justify-center font-bold shrink-0">{id + 1}</span>
                            <span className="text-slate-350 mt-0.5 leading-snug">{action}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Automated Containment Bash/Python Script */}
                    <div className="space-y-1.5 pt-3 border-t border-[#222]">
                      <div className="flex items-center justify-between select-none">
                        <span className="text-[9px] uppercase font-bold text-[#FF2E2E] font-mono flex items-center gap-1 tracking-wider">
                          <Terminal className="h-3 w-3 text-slate-650" />
                          Containment Playbook Command Script
                        </span>
                        <button
                          onClick={() => handleCopyScript(selectedAlert?.aiAnalysis?.remediationScript || "")}
                          className="text-slate-400 hover:text-white flex items-center gap-1 font-mono text-[10px] cursor-pointer"
                        >
                          {copiedState ? (
                            <>
                              <Check className="h-3 w-3 text-emerald-400" />
                              Copied!
                            </>
                          ) : (
                            <>
                              <Copy className="h-3 w-3 text-slate-500" />
                              Copy Playbook
                            </>
                          )}
                        </button>
                      </div>
                      <pre className="text-emerald-400 bg-neutral-950 p-3 rounded-none border border-[#222] font-mono text-[10px] overflow-x-auto whitespace-pre leading-relaxed select-all">
                        {selectedAlert.aiAnalysis.remediationScript}
                      </pre>
                    </div>

                  </div>
                )}

                {!selectedAlert.aiAnalysis && !isAiLoading && (
                  <div className="flex-grow flex flex-col justify-center items-center py-10 text-center text-slate-600 font-mono text-xs">
                    <Cpu className="h-8 w-8 text-neutral-800 mb-2" />
                    No intelligence report compiled yet. Request AI Audit analysis to construct full vector mitigation logs.
                  </div>
                )}
              </div>

            </div>
          )}

        </div>
      </div>

    </div>
  );
}
