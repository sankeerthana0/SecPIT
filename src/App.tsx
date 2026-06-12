import React, { useState, useEffect, useRef, useCallback } from "react";
import { LogEntry, ThreatRule, AlertEntry, AIAnalysisResult } from "./types";
import { 
  generateBenignLog, 
  generateAttackLog, 
  calculateEntropy, 
  INITIAL_RULES 
} from "./logGenerator";
import { 
  ShieldAlert, 
  Activity, 
  SlidersHorizontal, 
  Search, 
  Terminal, 
  Server,
  Layers,
  HelpCircle,
  Wifi,
  Workflow
} from "lucide-react";
import DashboardTab from "./components/DashboardTab";
import RulesTab from "./components/RulesTab";
import ExplorerTab from "./components/ExplorerTab";
import AlertsTab from "./components/AlertsTab";
import { motion, AnimatePresence } from "motion/react";

// Native oscillator audio advisor for security intrusions
function triggerIntrusionAudio() {
  try {
    const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();
    
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    
    osc.connect(gain);
    gain.connect(ctx.destination);
    
    osc.type = "sawtooth";
    osc.frequency.setValueAtTime(650, ctx.currentTime);
    osc.frequency.linearRampToValueAtTime(120, ctx.currentTime + 0.35);
    
    gain.gain.setValueAtTime(0.08, ctx.currentTime);
    gain.gain.linearRampToValueAtTime(0.001, ctx.currentTime + 0.35);
    
    osc.start(ctx.currentTime);
    osc.stop(ctx.currentTime + 0.4);
  } catch (err) {
    // Graceful error ignore on silent policies or headless browser testing
  }
}

export default function App() {
  const [activeTab, setActiveTab] = useState<"dashboard" | "rules" | "explorer" | "alerts">("dashboard");
  
  // High-performance state pools
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [alerts, setAlerts] = useState<AlertEntry[]>([]);
  const [rules, setRules] = useState<ThreatRule[]>(INITIAL_RULES);
  const [totalProcessedCount, setTotalProcessedCount] = useState(0);
  const [blacklistedIps, setBlacklistedIps] = useState<Set<string>>(new Set());

  // Kafka live stream state
  const [isStreaming, setIsStreaming] = useState(true);
  const [streamSpeed, setStreamSpeed] = useState(1000); // interval delay in ms

  // ML Detection parameters
  const [mlSensitivity, setMlSensitivity] = useState(0.65);
  const [mlEntropyThreshold, setMlEntropyThreshold] = useState(5.4);

  // References to bypass stale closures inside ingestion interval
  const rulesRef = useRef<ThreatRule[]>(rules);
  const blacklistedRef = useRef<Set<string>>(blacklistedIps);
  const mlEntropyRef = useRef<number>(mlEntropyThreshold);

  useEffect(() => { rulesRef.current = rules; }, [rules]);
  useEffect(() => { blacklistedRef.current = blacklistedIps; }, [blacklistedIps]);
  useEffect(() => { mlEntropyRef.current = mlEntropyThreshold; }, [mlEntropyThreshold]);

  // Core parser executing matching logic on every generated event log
  const parseIncomingLog = useCallback((log: LogEntry) => {
    const currentRules = rulesRef.current;
    const activeBlacklist = blacklistedRef.current;
    
    setTotalProcessedCount(prev => prev + 1);

    // 1. IP firewall check: If candidate host is already blacklisted/isolated, block request
    if (activeBlacklist.has(log.sourceIp)) {
      log.severity = "Medium";
      log.payload = `[DROP BLOCK - FIREWALL CONTROLLER v2.4] Packet dropped from banned entity ${log.sourceIp}`;
      setLogs(prev => [log, ...prev].slice(0, 500));
      return;
    }

    // 2. Signature engine scans
    let matchedRule: ThreatRule | null = null;
    for (const rule of currentRules) {
      if (rule.isEnabled && rule.engineType === "Signature") {
        const fieldToInspect = log[rule.targetField];
        if (fieldToInspect) {
          try {
            const compiledCheck = new RegExp(rule.pattern, "i");
            if (compiledCheck.test(String(fieldToInspect))) {
              matchedRule = rule;
              break;
            }
          } catch (regexpError) {
            console.error("Signature compilation parsing deviation:", regexpError);
          }
        }
      }
    }

    // 3. ML-Anomaly checks (if no signature fired)
    let isMlAnomaly = false;
    if (!matchedRule) {
      const calculatedThreshold = mlEntropyRef.current;
      // High-entropy strings are anomalies (e.g. encrypted commands or binary bypass streams)
      if (log.entropy >= calculatedThreshold && log.topic === "web-access-topic") {
        isMlAnomaly = true;
      }
    }

    // 4. Alert spawning & recording
    if (matchedRule) {
      // Trigger update on match counters
      setRules(prevRules => prevRules.map(r => 
        r.id === matchedRule!.id ? { ...r, matchedTimes: r.matchedTimes + 1 } : r
      ));

      const newAlert: AlertEntry = {
        id: `alert_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
        timestamp: new Date().toISOString(),
        ruleId: matchedRule.id,
        ruleName: matchedRule.ruleName,
        sourceIp: log.sourceIp,
        targetPort: log.targetPort,
        payload: log.payload || log.urlPath || log.command,
        message: `Threat detection match for pattern template of: ${matchedRule.description}`,
        severity: matchedRule.severity,
        engine: "Signature Core v2",
        status: "Unresolved"
      };

      setAlerts(prev => [newAlert, ...prev].slice(0, 200));
      log.severity = matchedRule.severity;
      triggerIntrusionAudio();
    } else if (isMlAnomaly) {
      const mlAlert: AlertEntry = {
        id: `alert_ml_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
        timestamp: new Date().toISOString(),
        ruleId: "ml_isolation_cluster",
        ruleName: "ML_Anomalous_Payload_Shannon_Entropy",
        sourceIp: log.sourceIp,
        targetPort: log.targetPort,
        payload: log.payload || log.urlPath,
        message: `Machine learning isolation identifies anomalous entropy index (${log.entropy.toFixed(3)} bits) on remote data incoming frame. Potential obfuscation detection.`,
        severity: "High",
        engine: "ML isolation engine",
        status: "Unresolved"
      };

      setAlerts(prev => [mlAlert, ...prev].slice(0, 200));
      log.severity = "High";
      triggerIntrusionAudio();
    }

    // Register log into historical search pool
    setLogs(prev => [log, ...prev].slice(0, 500));
  }, []);

  // Set up live ingestion polling loop
  useEffect(() => {
    if (!isStreaming) return;

    const pipelineLoop = setInterval(() => {
      // 12% probability of threat event, 88% typical benign microservice telemetry
      const rateCheck = Math.random() < 0.12;
      const parsedDocument = rateCheck ? generateAttackLog() : generateBenignLog();
      parseIncomingLog(parsedDocument);
    }, streamSpeed);

    return () => clearInterval(pipelineLoop);
  }, [isStreaming, streamSpeed, parseIncomingLog]);

  // Handle immediate manual logs injection
  const handleInjectManualLog = (url: string, payload: string, headers: string, port: number) => {
    const customLog: LogEntry = {
      id: `manual_log_${Date.now()}`,
      timestamp: new Date().toISOString(),
      sourceIp: "127.0.0.1",
      targetPort: port,
      method: "POST",
      urlPath: url,
      payload,
      headers,
      entropy: calculateEntropy(payload || url || ""),
      severity: "Low",
      topic: "web-access-topic"
    };
    parseIncomingLog(customLog);
  };

  // Inject a specific attack blueprint instance directly
  const handleInjectAttack = (idx: number) => {
    const attackLog = generateAttackLog(idx);
    parseIncomingLog(attackLog);
  };

  // Rule operations: togglers and appenders
  const handleToggleRule = (id: string) => {
    setRules(prev => prev.map(r => r.id === id ? { ...r, isEnabled: !r.isEnabled } : r));
  };

  const handleRemoveRule = (id: string) => {
    setRules(prev => prev.filter(r => r.id !== id));
  };

  const handleAddCustomRule = (compiledRule: Omit<ThreatRule, "id" | "matchedTimes">) => {
    const rawId = `rule_custom_${Date.now()}`;
    const fresh: ThreatRule = {
      ...compiledRule,
      id: rawId,
      matchedTimes: 0
    };
    setRules(prev => [fresh, ...prev]);
  };

  // Alert Incident responses
  const handleAcknowledgeAlert = (id: string) => {
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: "Acknowledged" } : a));
  };

  const handleBlockIp = (alertId: string, ip: string) => {
    // 1. Block/firewall the IP inside our runtime simulator ref
    setBlacklistedIps(prev => {
      const updated = new Set(prev);
      updated.add(ip);
      return updated;
    });

    // 2. Set alert response to Contained/Blocked
    setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status: "Blocked" } : a));
  };

  const handleSetAiAnalysis = (alertId: string, info: AIAnalysisResult) => {
    setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, aiAnalysis: info } : a));
  };

  const handleClearLogs = () => {
    setLogs([]);
  };

  return (
    <div className="min-h-screen bg-[#050505] text-[#E0E0E0] flex flex-col font-sans selection:bg-cyan-500 selection:text-slate-950 border-[12px] border-[#1A1A1A]">
      
      {/* GLOBAL NAVBAR COMPONENT */}
      <header className="bg-[#050505] border-b border-[#222] sticky top-0 z-50 px-4 sm:px-10 py-6">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
          <div className="flex flex-col">
            <div className="flex items-center gap-3 mb-2">
              <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-[0_0_8px_#00F0FF] animate-pulse"></div>
              <span className="text-[10px] tracking-[0.4em] text-cyan-400 font-bold uppercase font-mono">Live Neural Mesh Ingress</span>
            </div>
            <h1 className="text-4xl sm:text-5xl font-display font-black tracking-tighter leading-none uppercase italic text-white">
              AEGIS SECURITY COCKPIT
            </h1>
          </div>

          {/* STATUS INTEGRATION LIGHTS */}
          <div className="flex flex-wrap gap-6 sm:gap-16 text-right font-sans">
            <div className="flex flex-col items-start md:items-end">
              <span className="text-[9px] uppercase tracking-widest text-slate-500 font-semibold mb-1 font-mono">Active Threats</span>
              <span className="text-3xl font-black text-rose-500 font-display italic">
                {String(alerts.filter(a => a.status === "Unresolved").length).padStart(2, '0')}
              </span>
            </div>
            <div className="flex flex-col items-start md:items-end">
              <span className="text-[9px] uppercase tracking-widest text-slate-500 font-semibold mb-1 font-mono">Pipeline Health</span>
              <span className="text-3xl font-black text-white font-display italic">
                99.9<span className="text-sm text-slate-600 font-bold ml-0.5">%</span>
              </span>
            </div>
            <div className="flex flex-col items-start md:items-end">
              <span className="text-[9px] uppercase tracking-widest text-slate-500 font-semibold mb-1 font-mono">Total Ingested</span>
              <span className="text-3xl font-black text-cyan-400 font-mono">
                {totalProcessedCount}
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* DASHBOARD WORKSPACE PANELS CONTAINER */}
      <main className="flex-grow max-w-7xl w-full mx-auto p-4 sm:p-6 space-y-8">
        
        {/* VIEW NAVIGATION CARDS */}
        <div className="flex flex-wrap bg-[#111111] border border-[#222] p-1 rounded-sm w-full md:w-max gap-1">
          <button
            onClick={() => setActiveTab("dashboard")}
            className={`flex-1 md:flex-initial flex items-center justify-center gap-2 py-2.5 px-6 rounded-xs text-xs font-black uppercase tracking-wider font-display transition duration-200 cursor-pointer ${
              activeTab === "dashboard" 
                ? "bg-cyan-400 text-slate-950 italic" 
                : "text-slate-400 hover:text-white hover:bg-[#1a1a1a]"
            }`}
          >
            <Activity className="h-4 w-4" />
            Live Stream Cockpit
          </button>
          
          <button
            onClick={() => setActiveTab("rules")}
            className={`flex-1 md:flex-initial flex items-center justify-center gap-2 py-2.5 px-6 rounded-xs text-xs font-black uppercase tracking-wider font-display transition duration-200 cursor-pointer ${
              activeTab === "rules" 
                ? "bg-cyan-400 text-slate-950 italic"
                : "text-slate-400 hover:text-white hover:bg-[#1a1a1a]"
            }`}
          >
            <SlidersHorizontal className="h-4 w-4" />
            Detection Rules
          </button>

          <button
            onClick={() => setActiveTab("explorer")}
            className={`flex-1 md:flex-initial flex items-center justify-center gap-2 py-2.5 px-6 rounded-xs text-xs font-black uppercase tracking-wider font-display transition duration-200 cursor-pointer ${
              activeTab === "explorer" 
                ? "bg-cyan-400 text-slate-950 italic"
                : "text-slate-400 hover:text-white hover:bg-[#1a1a1a]"
            }`}
          >
            <Search className="h-4 w-4" />
            Elastic Explorer
          </button>

          <button
            onClick={() => setActiveTab("alerts")}
            className={`flex-1 md:flex-initial flex items-center justify-center gap-2 py-2.5 px-6 rounded-xs text-xs font-black uppercase tracking-wider font-display transition duration-200 cursor-pointer relative ${
              activeTab === "alerts" 
                ? "bg-cyan-400 text-slate-950 italic"
                : "text-slate-400 hover:text-white hover:bg-[#1a1a1a]"
            }`}
          >
            <ShieldAlert className="h-4 w-4" />
            Alerts Center
            {alerts.filter(a => a.status === "Unresolved").length > 0 && (
              <span className="absolute -top-1 -right-1 bg-rose-600 text-white font-bold font-mono text-[9px] h-5 w-5 rounded-full flex items-center justify-center border border-slate-950 shadow-[0_0_6px_rgba(239,68,68,0.7)]">
                {alerts.filter(a => a.status === "Unresolved").length}
              </span>
            )}
          </button>
        </div>

        {/* TAB WORKSPACE MOUNTING WITH MOTION TRANSITION */}
        <div className="outline-none">
          {activeTab === "dashboard" && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2 }}>
              <DashboardTab
                logs={logs}
                alerts={alerts}
                totalProcessed={totalProcessedCount}
                isStreaming={isStreaming}
                setIsStreaming={setIsStreaming}
                speed={streamSpeed}
                setSpeed={setStreamSpeed}
                onClearLogs={handleClearLogs}
                onInjectAttack={handleInjectAttack}
                onInjectManualLog={handleInjectManualLog}
                blacklistedIps={blacklistedIps}
              />
            </motion.div>
          )}

          {activeTab === "rules" && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2 }}>
              <RulesTab
                rules={rules}
                onToggleRule={handleToggleRule}
                onRemoveRule={handleRemoveRule}
                onAddCustomRule={handleAddCustomRule}
                mlSensitivity={mlSensitivity}
                setMlSensitivity={setMlSensitivity}
                mlEntropyThreshold={mlEntropyThreshold}
                setMlEntropyThreshold={setMlEntropyThreshold}
              />
            </motion.div>
          )}

          {activeTab === "explorer" && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2 }}>
              <ExplorerTab logs={logs} />
            </motion.div>
          )}

          {activeTab === "alerts" && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2 }}>
              <AlertsTab
                alerts={alerts}
                logs={logs}
                onAcknowledgeAlert={handleAcknowledgeAlert}
                onBlockIp={handleBlockIp}
                onSetAiAnalysis={handleSetAiAnalysis}
                blacklistedIps={blacklistedIps}
              />
            </motion.div>
          )}
        </div>

      </main>

      {/* SECURE SPACE FOOTER CREDITS */}
      <footer className="mt-12 py-8 border-t border-[#222] bg-[#050505] flex flex-col md:flex-row justify-between items-center gap-6 px-4 sm:px-10">
        <div className="flex flex-col sm:flex-row gap-6 sm:gap-12 items-start sm:items-center">
          <div className="flex flex-col">
            <span className="text-[8px] uppercase tracking-widest text-[#475569] mb-1 font-bold font-mono">Core Platform</span>
            <div className="flex gap-3 text-xs font-black tracking-tight text-white font-display">
              <span>PYTHON 3.11</span>
              <span className="text-[#334155]">/</span>
              <span>JAVA 17</span>
              <span className="text-[#334155]">/</span>
              <span>KAFKA CLUSTER</span>
            </div>
          </div>
          <div className="flex flex-col">
            <span className="text-[8px] uppercase tracking-widest text-[#475569] mb-1 font-bold font-mono">Simulated Stack</span>
            <div className="flex gap-3 text-xs font-black tracking-tight text-white font-display">
              <span>ELASTICSTACK</span>
              <span className="text-[#334155]">/</span>
              <span>DOCKER TELEMETRY</span>
              <span className="text-[#334155]">/</span>
              <span>GEMINI AI COGNITION</span>
            </div>
          </div>
        </div>
        <div className="text-right">
          <span className="text-[10px] font-mono text-[#475569] uppercase tracking-tighter block">
            SECURE CLUSTER ID: aistudio-threat-engine-3000
          </span>
          <span className="text-[9px] font-mono text-[#334155] uppercase tracking-tighter mt-1 block">
            Build: v2024.11.08_Alpha_Branch
          </span>
        </div>
      </footer>

    </div>
  );
}
