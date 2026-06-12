import React, { useState } from "react";
import { ThreatRule, SeverityType } from "../types";
import { 
  ShieldCheck, 
  ShieldAlert, 
  Sparkles, 
  Trash2, 
  CheckCircle, 
  X, 
  Cpu, 
  Command, 
  Info,
  SlidersHorizontal,
  ChevronRight
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";

interface RulesTabProps {
  rules: ThreatRule[];
  onToggleRule: (id: string) => void;
  onRemoveRule: (id: string) => void;
  onAddCustomRule: (rule: Omit<ThreatRule, "id" | "matchedTimes">) => void;
  mlSensitivity: number;
  setMlSensitivity: (n: number) => void;
  mlEntropyThreshold: number;
  setMlEntropyThreshold: (n: number) => void;
}

export default function RulesTab({
  rules,
  onToggleRule,
  onRemoveRule,
  onAddCustomRule,
  mlSensitivity,
  setMlSensitivity,
  mlEntropyThreshold,
  setMlEntropyThreshold
}: RulesTabProps) {
  // Local states for custom manual rule forms
  const [showManualRuleForm, setShowManualRuleForm] = useState(false);
  const [newRuleName, setNewRuleName] = useState("wp_admin_login_probe");
  const [newRuleSeverity, setNewRuleSeverity] = useState<SeverityType>("High");
  const [newRuleCategory, setNewRuleCategory] = useState("Bypasses");
  const [newRuleDescription, setNewRuleDescription] = useState("Detects attempts to scan or brute-force WordPress login endpoints directly.");
  const [newRulePattern, setNewRulePattern] = useState("\\/wp-login\\.php|\\/wp-admin\\/");
  const [newRuleTargetField, setNewRuleTargetField] = useState<any>("urlPath");

  // State for AI-powered signature generator
  const [aiRuleDescription, setAiRuleDescription] = useState("");
  const [isAiCompiling, setIsAiCompiling] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [aiSuccessMsg, setAiSuccessMsg] = useState<string | null>(null);

  const handleManualRuleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRuleName || !newRulePattern) return;
    
    onAddCustomRule({
      ruleName: newRuleName.trim(),
      severity: newRuleSeverity,
      category: newRuleCategory,
      description: newRuleDescription,
      pattern: newRulePattern,
      targetField: newRuleTargetField,
      isEnabled: true,
      engineType: "Signature",
      recommendedMitigation: "Block offending IP using rule block sets."
    });

    setShowManualRuleForm(false);
    // Reset form
    setNewRuleName("wp_admin_login_probe");
    setNewRulePattern("\\/wp-login\\.php|\\/wp-admin\\/");
  };

  const handleAiCompileRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!aiRuleDescription.trim()) return;

    setIsAiCompiling(true);
    setAiError(null);
    setAiSuccessMsg(null);

    try {
      const res = await fetch("/api/generate-signature", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ attackDescription: aiRuleDescription })
      });

      if (!res.ok) {
        throw new Error("Target response state is unhealthy. Failed compiling rule.");
      }

      const generatedRule = await res.json();
      
      onAddCustomRule({
        ruleName: generatedRule.ruleName || "ai_compiled_signature",
        severity: (generatedRule.severity as SeverityType) || "High",
        category: generatedRule.category || "General Threat",
        description: generatedRule.description || "Synthesised from AI prompt analysis.",
        pattern: generatedRule.pattern || ".*",
        targetField: generatedRule.targetField || "payload",
        isEnabled: true,
        engineType: "Signature",
        recommendedMitigation: generatedRule.recommendedMitigation || "Examine security rules configuration parameters."
      });

      setAiSuccessMsg(`System rule compiling completed! Loaded '${generatedRule.ruleName}' into Signature Core.`);
      setAiRuleDescription("");
    } catch (err: any) {
      console.error(err);
      setAiError(err.message || "Failed calling Gemini generation service. Check system logs.");
    } finally {
      setIsAiCompiling(false);
    }
  };

  const signatureRules = rules.filter(r => r.engineType === "Signature");

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6" id="rules_tab_root">
      
      {/* LEFT COLUMN PANEL: SIGNATURE DATABASE */}
      <div className="lg:col-span-2 space-y-6">
        <div className="bg-[#0D0D0D] border border-[#222] rounded-none p-6">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-6 border-b border-[#222] pb-4">
            <div>
              <h3 className="text-sm font-black text-white font-display uppercase tracking-wider italic">Signature Rule-set Engine (Core v2)</h3>
              <p className="text-[11px] text-slate-550 font-mono mt-0.5">Regular expression match rules processed sequentially on incoming event fields.</p>
            </div>
            <button 
              onClick={() => setShowManualRuleForm(!showManualRuleForm)}
              className="text-xs text-white bg-neutral-900 border border-[#333] hover:bg-neutral-850 hover:border-neutral-600 font-bold uppercase font-mono px-4 py-2 rounded-none transition duration-155 cursor-pointer"
            >
              {showManualRuleForm ? "Close Form" : "+ Create Custom Rule"}
            </button>
          </div>

          {/* Form to insert custom manual rule */}
          <AnimatePresence>
            {showManualRuleForm && (
              <motion.div 
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                className="overflow-hidden mb-6"
              >
                <form onSubmit={handleManualRuleSubmit} className="bg-[#050505] rounded-none p-5 border border-[#222] space-y-4 text-xs">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-[9px] uppercase font-bold text-slate-500 mb-1 font-mono tracking-widest">Rule name (snake_case)</label>
                      <input 
                        type="text" 
                        value={newRuleName} 
                        onChange={e => setNewRuleName(e.target.value)} 
                        className="w-full bg-[#050505] border border-[#222] rounded-none p-2.5 text-white font-mono focus:border-[#00F0FF] focus:outline-none"
                        required 
                      />
                    </div>
                    <div>
                      <label className="block text-[9px] uppercase font-bold text-slate-500 mb-1 font-mono tracking-widest">Severity Rating</label>
                      <select 
                        value={newRuleSeverity} 
                        onChange={e => setNewRuleSeverity(e.target.value as any)} 
                        className="w-full bg-[#050505] border border-[#222] rounded-none p-2.5 text-white font-mono focus:border-[#00F0FF] focus:outline-none"
                      >
                        <option value="Low">Low (Audit / Info)</option>
                        <option value="Medium">Medium (Suspicious Activity)</option>
                        <option value="High">High (Active Probing)</option>
                        <option value="Critical">Critical (Remote Execution)</option>
                      </select>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-[9px] uppercase font-bold text-slate-500 mb-1 font-mono tracking-widest">Threat Category</label>
                      <input 
                        type="text" 
                        value={newRuleCategory} 
                        onChange={e => setNewRuleCategory(e.target.value)} 
                        className="w-full bg-[#050505] border border-[#222] rounded-none p-2.5 text-white focus:border-[#00F0FF] focus:outline-none font-mono"
                        placeholder="Intrusion"
                      />
                    </div>
                    <div>
                      <label className="block text-[9px] uppercase font-bold text-slate-500 mb-1 font-mono tracking-widest">Target field to match</label>
                      <select 
                        value={newRuleTargetField} 
                        onChange={e => setNewRuleTargetField(e.target.value as any)} 
                        className="w-full bg-[#050505] border border-[#222] rounded-none p-2.5 text-white font-mono focus:border-[#00F0FF] focus:outline-none"
                      >
                        <option value="urlPath">urlPath (Web Address URI)</option>
                        <option value="payload">payload (Data Body / syslog msg)</option>
                        <option value="headers">headers (HTTP User Agent / headers)</option>
                        <option value="username">username (Auth Login values)</option>
                        <option value="command">command (Terminal process commands)</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-[9px] uppercase font-bold text-slate-500 mb-1 font-mono tracking-widest">RegExp Match Pattern</label>
                    <input 
                      type="text" 
                      value={newRulePattern} 
                      onChange={e => setNewRulePattern(e.target.value)} 
                      className="w-full bg-[#050505] border border-[#222] rounded-none p-2.5 text-[#FF2E2E] font-mono tracking-wide focus:border-[#00F0FF] focus:outline-none"
                      placeholder="(\\.\\./|/etc/passwd)"
                      required 
                    />
                  </div>

                  <div>
                    <label className="block text-[9px] uppercase font-bold text-slate-500 mb-1 font-mono tracking-widest">Rule Description</label>
                    <textarea 
                      value={newRuleDescription} 
                      onChange={e => setNewRuleDescription(e.target.value)} 
                      rows={2}
                      className="w-full bg-[#050505] border border-[#222] rounded-none p-2.5 text-white focus:border-[#00F0FF] focus:outline-none font-mono"
                      placeholder="Detailed context of what security state is flagged..."
                    />
                  </div>

                  <div className="flex justify-end gap-2 text-xs font-mono">
                    <button 
                      type="button" 
                      onClick={() => setShowManualRuleForm(false)} 
                      className="px-3 py-1.5 text-slate-500 hover:text-white cursor-pointer"
                    >
                      Dismiss
                    </button>
                    <button 
                      type="submit" 
                      className="bg-[#00F0FF] hover:bg-cyan-400 text-slate-950 font-black italic uppercase font-display px-4 py-1.5 rounded-none transition cursor-pointer"
                    >
                      Compile and Inject Rule
                    </button>
                  </div>
                </form>
              </motion.div>
            )}
          </AnimatePresence>

          {/* ACTIVE RULES ROWS */}
          <div className="space-y-3">
            {signatureRules.map((rule) => (
              <div 
                key={rule.id} 
                className={`p-4 rounded-none border transition-colors ${
                  rule.isEnabled 
                    ? "bg-[#050505] border-[#222] hover:border-neutral-700" 
                    : "bg-[#050505]/20 border-[#222]/40 text-slate-600"
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="flex items-start gap-3">
                    <div className="pt-0.5">
                      {rule.isEnabled ? (
                        <ShieldCheck className="h-4.5 w-4.5 text-[#00F0FF]" />
                      ) : (
                        <ShieldAlert className="h-4.5 w-4.5 text-slate-700" />
                      )}
                    </div>
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`font-mono text-xs font-bold ${rule.isEnabled ? "text-white" : "text-slate-600"}`}>
                          {rule.ruleName}
                        </span>
                        <span className={`text-[8px] font-extrabold uppercase px-1.5 py-0.5 rounded-none font-mono border ${
                          rule.severity === "Critical" 
                            ? "bg-[#251011] border-[#FF2E2E]/40 text-[#FF2E2E]"
                            : rule.severity === "High" 
                              ? "bg-[#251011] border-[#FF2E2E]/25 text-[#FF2E2E]/80"
                              : "bg-[#1d120a] border-amber-900/40 text-amber-500"
                        }`}>
                          {rule.severity}
                        </span>
                        <span className="text-[10px] text-slate-500 font-mono">
                          Target: <span className="text-[#00F0FF] font-bold">{rule.targetField}</span>
                        </span>
                      </div>
                      <p className="text-[11.5px] text-slate-400 mt-1 leading-relaxed">{rule.description}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 self-end sm:self-auto pl-7 sm:pl-0 font-mono">
                    <div className="text-right text-[10px] text-slate-550">
                      Matches: <span className="text-[#FF2E2E] font-black text-xs">{rule.matchedTimes}</span>
                    </div>

                    <div className="flex items-center gap-2">
                      <button 
                        onClick={() => onToggleRule(rule.id)}
                        className={`text-[9px] font-extrabold px-2.5 py-1 rounded-none uppercase transition-all tracking-wider cursor-pointer border ${
                          rule.isEnabled 
                            ? "bg-[#0b1b11] text-emerald-400 border-emerald-900/45 hover:bg-emerald-950/20" 
                            : "bg-neutral-900 text-slate-500 border-neutral-800 hover:bg-neutral-850"
                        }`}
                      >
                        {rule.isEnabled ? "ENABLED" : "MUTED"}
                      </button>

                      {rule.id.startsWith("rule_custom_") && (
                        <button 
                          onClick={() => onRemoveRule(rule.id)}
                          className="text-slate-600 hover:text-[#FF2E2E] p-1.5 rounded-none hover:bg-neutral-900 transition-colors cursor-pointer"
                          title="Remove custom rule"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      )}
                    </div>
                  </div>
                </div>

                {rule.isEnabled && (
                  <div className="mt-3 bg-neutral-950 p-2.5 rounded-none border border-[#222]/60 font-mono text-[11px] text-[#FF2E2E] overflow-x-auto whitespace-pre">
                    <span className="text-slate-650 uppercase font-sans text-[8px] font-extrabold tracking-widest mr-2 select-none">REGEX:</span>
                    {rule.pattern}
                  </div>
                )}
              </div>
            ))}
          </div>

        </div>
      </div>

      {/* RIGHT SIDEBAR: AI RULE BUILDER & ML ANOMALY ENGINE */}
      <div className="space-y-6">
        
        {/* PANEL: AI-POWERED RULE COMPILER */}
        <div className="bg-[#0D0D0D] border border-[#222] rounded-none p-5">
          <div className="flex items-center gap-1.5 mb-2.5">
            <Sparkles className="h-4.5 w-4.5 text-[#00F0FF] animate-pulse" />
            <h3 className="text-sm font-black text-white font-display uppercase tracking-wider italic">AI Rule Compiler & Synthesizer</h3>
          </div>
          <p className="text-[11px] text-slate-500 font-mono leading-relaxed mb-4">
            Briefly describe any emerging CVE, backdoor request or intrusion footprint. Gemini is wired to dynamically translate specifications down to Regex matrices.
          </p>

          <form onSubmit={handleAiCompileRule} className="space-y-3.5 text-xs">
            <div>
              <textarea 
                value={aiRuleDescription}
                onChange={e => setAiRuleDescription(e.target.value)}
                placeholder="Detail transaction threats (e.g. 'SSH payload contains interactive script commands executing from strange ports')"
                rows={4}
                className="w-full bg-[#050505] text-xs border border-[#222] rounded-none p-2.5 text-white placeholder-slate-600 focus:border-[#00F0FF] focus:outline-none font-mono"
                disabled={isAiCompiling}
                required
              />
            </div>

            {aiError && (
              <div className="bg-[#251011] text-rose-355 p-2.5 rounded-none border border-[#FF2E2E]/20 font-mono text-[10px]">
                {aiError}
              </div>
            )}

            {aiSuccessMsg && (
              <div className="bg-[#0b1b11] text-emerald-305 p-2.5 rounded-none border border-emerald-900/50 font-mono text-[10px] flex items-center gap-1.5">
                <CheckCircle className="h-4 w-4 text-emerald-400 shrink-0" />
                {aiSuccessMsg}
              </div>
            )}

            <button
              type="submit"
              disabled={isAiCompiling || !aiRuleDescription.trim()}
              className={`w-full py-2.5 rounded-none text-xs font-bold uppercase tracking-wider font-mono transition flex items-center justify-center gap-2 cursor-pointer ${
                isAiCompiling 
                  ? "bg-slate-850 text-slate-550 border border-[#222] cursor-not-allowed" 
                  : "bg-[#00F0FF] hover:bg-cyan-400 text-slate-950 font-black italic font-display"
              }`}
            >
              {isAiCompiling ? (
                <>
                  <div className="animate-spin rounded-full h-3 w-3 border-2 border-slate-550 border-t-cyan-400"></div>
                  Compiling Signature...
                </>
              ) : (
                <>
                  <Sparkles className="h-3.5 w-3.5" />
                  Synthesize & Inject
                </>
              )}
            </button>
          </form>
        </div>

        {/* PANEL: MACHINE LEARNING ANOMALY COEFFICIENTS */}
        <div className="bg-[#0D0D0D] border border-[#222] rounded-none p-5">
          <div className="flex items-center gap-1.5 mb-2.5">
            <Cpu className="h-4 w-4 text-[#00F0FF]" />
            <h3 className="text-sm font-black text-white font-display uppercase tracking-wider italic">ML Anomaly engine</h3>
          </div>
          <p className="text-[11px] text-slate-500 font-mono leading-relaxed mb-4">
            Continuous real-time Shannon Entropy log telemetry analyzing unstructured data anomalies.
          </p>

          <div className="space-y-5">
            {/* Entropy threshold slider */}
            <div className="space-y-1.5">
              <div className="flex justify-between items-center text-xs font-mono text-slate-450">
                <span>Shannon Entropy Limit</span>
                <span className="text-[#00F0FF] font-black">{mlEntropyThreshold.toFixed(1)} bits</span>
              </div>
              <input 
                type="range" 
                min={4.0}
                max={6.5}
                step={0.1}
                value={mlEntropyThreshold}
                onChange={e => setMlEntropyThreshold(Number(e.target.value))}
                className="w-full accent-cyan-400 h-1 bg-neutral-900 cursor-pointer"
              />
              <p className="text-[10px] text-slate-600 leading-tight font-mono">
                Payload frame information density higher than threshold flags heuristic alarm triggers.
              </p>
            </div>

            {/* Sensitivity multiplier slider */}
            <div className="space-y-1.5">
              <div className="flex justify-between items-center text-xs font-mono text-slate-450">
                <span>Detection Sensitivity</span>
                <span className="text-[#00F0FF] font-black">{(mlSensitivity * 100).toFixed(0)}%</span>
              </div>
              <input 
                type="range" 
                min={0.1}
                max={1.0}
                step={0.05}
                value={mlSensitivity}
                onChange={e => setMlSensitivity(Number(e.target.value))}
                className="w-full accent-cyan-400 h-1 bg-neutral-900 cursor-pointer"
              />
              <p className="text-[10px] text-slate-600 leading-tight font-mono">
                Confidence triggers parameters mapping anomalous node interactions.
              </p>
            </div>

            {/* Simulated Live Tensor Metrics */}
            <div className="bg-[#050505] p-3.5 border border-[#222] space-y-1.5 text-[11px] font-mono text-slate-450">
              <div className="flex justify-between">
                <span>Core state:</span>
                <span className="text-emerald-400 font-bold">TensorFlow VM Running</span>
              </div>
              <div className="flex justify-between">
                <span>Total baselines:</span>
                <span className="text-white">1,504 IP signatures mapped</span>
              </div>
              <div className="flex justify-between">
                <span>Clustered rate:</span>
                <span className="text-white">0.024 ms / frame</span>
              </div>
              <div className="flex justify-between font-bold">
                <span>Heuristic state:</span>
                <span className="text-[#00F0FF]">Standard drift matched</span>
              </div>
            </div>
          </div>
        </div>

      </div>

    </div>
  );
}
