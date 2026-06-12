import React, { useState } from "react";
import { 
  ResponsiveContainer, 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  Tooltip, 
  CartesianGrid, 
  BarChart, 
  Bar, 
  Cell 
} from "recharts";
import { LogEntry, AlertEntry, KafkaTopicStats } from "../types";
import { 
  Play, 
  Pause, 
  Zap, 
  Layers, 
  Server, 
  Terminal, 
  AlertTriangle, 
  Activity, 
  Trash2, 
  Gauge
} from "lucide-react";
import { ATTACK_BLUEPRINTS } from "../logGenerator";
import { motion, AnimatePresence } from "motion/react";

interface DashboardTabProps {
  logs: LogEntry[];
  alerts: AlertEntry[];
  totalProcessed: number;
  isStreaming: boolean;
  setIsStreaming: (s: boolean) => void;
  speed: number;
  setSpeed: (n: number) => void;
  onClearLogs: () => void;
  onInjectAttack: (idx: number) => void;
  onInjectManualLog: (url: string, payload: string, headers: string, port: number) => void;
  blacklistedIps: Set<string>;
}

export default function DashboardTab({
  logs,
  alerts,
  totalProcessed,
  isStreaming,
  setIsStreaming,
  speed,
  setSpeed,
  onClearLogs,
  onInjectAttack,
  onInjectManualLog,
  blacklistedIps
}: DashboardTabProps) {
  // Manual ingestion injection tools state
  const [showManualForm, setShowManualForm] = useState(false);
  const [manualUrl, setManualUrl] = useState("/api/users/profile");
  const [manualPayload, setManualPayload] = useState('{"id": 42}');
  const [manualHeaders, setManualHeaders] = useState('{"User-Agent":"Curl/8.4"}');
  const [manualPort, setManualPort] = useState(443);

  // Stats calculation over latest log windows
  const latestLogs = logs.slice(0, 50);
  const activeAlertsCount = alerts.filter(a => a.status === "Unresolved").length;

  // Calculate Kafka partition metrics
  const kafkaStats: KafkaTopicStats[] = [
    { name: "auth-topic", throughput: isStreaming ? Math.min(25, Math.round(1000 / speed * 0.3)) : 0, lag: Math.round(logs.length * 0.05), partitions: 4 },
    { name: "web-access-topic", throughput: isStreaming ? Math.min(65, Math.round(1000 / speed * 0.5)) : 0, lag: Math.round(logs.length * 0.02), partitions: 8 },
    { name: "syslog-topic", throughput: isStreaming ? Math.min(15, Math.round(1000 / speed * 0.2)) : 0, lag: Math.round(logs.length * 0.08), partitions: 2 },
  ];

  // Compile line chart data for last 10 points
  const recentSecondsData = Array.from({ length: 8 }).map((_, i) => {
    const secVal = 8 - i;
    const timeLowerBound = Date.now() - secVal * 2000;
    const timeUpperBound = Date.now() - (secVal - 1) * 2000;
    
    const countInWindow = logs.filter(l => {
      const t = new Date(l.timestamp).getTime();
      return t >= timeLowerBound && t < timeUpperBound;
    }).length;

    const alertsInWindow = alerts.filter(a => {
      const t = new Date(a.timestamp).getTime();
      return t >= timeLowerBound && t < timeUpperBound;
    }).length;

    return {
      time: `-${secVal * 2}s`,
      Logs: countInWindow,
      Threats: alertsInWindow
    };
  });

  // Category counts for Recharts bar chart
  const categoriesMap: Record<string, number> = {};
  alerts.forEach(a => {
    const name = a.ruleName.replace(/_/g, " ");
    categoriesMap[name] = (categoriesMap[name] || 0) + 1;
  });
  const categoryData = Object.entries(categoriesMap).map(([name, count]) => ({
    name: name.length > 18 ? name.substring(0, 16) + "..." : name,
    Count: count
  })).slice(0, 5);

  const handleManualSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onInjectManualLog(manualUrl, manualPayload, manualHeaders, Number(manualPort));
    setShowManualForm(false);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6" id="dashboard_tab_root">
      
      {/* LEFT & CENTER CLUSTER: Metrics, Chart, Ingestion Feed */}
      <div className="lg:col-span-2 space-y-6">
        
        {/* Row 1: Glowing Stats Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="bg-[#0D0D0D] border border-[#222] rounded-none p-4.5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-[10px] font-bold uppercase tracking-widest text-[#64748b] font-mono">Processed events</span>
              <Activity className="h-4 w-4 text-[#00F0FF] animate-pulse" />
            </div>
            <div className="mt-3">
              <span className="text-3xl font-black font-display tracking-tighter italic text-white">{totalProcessed}</span>
              <span className="text-[9px] block text-slate-500 font-mono mt-1 uppercase tracking-widest">Kafka Ingress stream</span>
            </div>
          </div>

          <div className="bg-[#0D0D0D] border border-[#222] rounded-none p-4.5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-[10px] font-bold uppercase tracking-widest text-[#64748b] font-mono">Active Threats</span>
              <AlertTriangle className={`h-4 w-4 ${activeAlertsCount > 0 ? "text-[#FF2E2E] animate-bounce" : "text-yellow-500"}`} />
            </div>
            <div className="mt-3">
              <span className="text-3xl font-black font-display tracking-tighter italic text-[#FF2E2E]">{alerts.length}</span>
              <span className="text-[9px] block text-slate-550 font-mono mt-1 uppercase tracking-widest">{activeAlertsCount} Unacknowledged</span>
            </div>
          </div>

          <div className="bg-[#0D0D0D] border border-[#222] rounded-none p-4.5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-[10px] font-bold uppercase tracking-widest text-[#64748b] font-mono">Calculated Entropy</span>
              <Gauge className="h-4 w-4 text-[#00F0FF]" />
            </div>
            <div className="mt-3">
              <span className="text-3xl font-black font-display tracking-tighter italic text-[#00F0FF]">
                {logs.length > 0 ? (logs.reduce((acc, cr) => acc + cr.entropy, 0) / logs.length).toFixed(3) : "0.000"}
              </span>
              <span className="text-[9px] block text-slate-550 font-mono mt-1 uppercase tracking-widest">Avg Shannon Index</span>
            </div>
          </div>

          <div className="bg-[#0D0D0D] border border-[#222] rounded-none p-4.5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-[10px] font-bold uppercase tracking-widest text-[#64748b] font-mono">Blocked entities</span>
              <Server className="h-4 w-4 text-amber-500" />
            </div>
            <div className="mt-3">
              <span className="text-3xl font-black font-display tracking-tighter italic text-amber-500">
                {blacklistedIps.size}
              </span>
              <span className="text-[9px] block text-slate-550 font-mono mt-1 uppercase tracking-widest">Isolated hosts</span>
            </div>
          </div>
        </div>

        {/* Row 2: Ingestion Chart Area */}
        <div className="bg-[#0D0D0D] border border-[#222] rounded-none p-6">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 mb-6">
            <div>
              <h3 className="text-sm font-black text-white uppercase tracking-wider font-display italic">Live Event Flow & Threat Ratio</h3>
              <p className="text-[11px] text-slate-500 font-mono">Throughput relative to 2-second telemetry partitions.</p>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono">
              <span className="flex items-center gap-1.5 font-bold uppercase text-[10px] text-slate-450">
                <span className="h-2 w-2 rounded-none bg-[#00F0FF] block"></span> Logs
              </span>
              <span className="flex items-center gap-1.5 font-bold uppercase text-[10px] text-slate-450">
                <span className="h-2 w-2 rounded-none bg-[#FF2E2E] block"></span> Alerts
              </span>
            </div>
          </div>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={recentSecondsData}>
                <CartesianGrid strokeDasharray="2 2" stroke="#222222" />
                <XAxis dataKey="time" stroke="#444444" fontSize={10} tickLine={false} fontClassName="font-mono" />
                <YAxis stroke="#444444" fontSize={10} tickLine={false} fontClassName="font-mono" />
                <Tooltip 
                  contentStyle={{ backgroundColor: "#070707", borderColor: "#222222", color: "#fff", fontClassName: "font-mono" }}
                  labelStyle={{ color: "#666666" }}
                />
                <Line type="monotone" dataKey="Logs" stroke="#00F0FF" strokeWidth={3} dot={{ r: 1 }} activeDot={{ r: 3 }} />
                <Line type="monotone" dataKey="Threats" stroke="#FF2E2E" strokeWidth={3} dot={{ r: 1 }} activeDot={{ r: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Row 3: Active Event Log Feed */}
        <div className="bg-[#0D0D0D] border border-[#222] rounded-none p-6">
          <div className="flex items-center justify-between mb-4 border-b border-[#222] pb-3">
            <div className="flex items-center gap-2">
              <Terminal className="h-4 w-4 text-[#00F0FF]" />
              <h3 className="text-sm font-black text-white uppercase tracking-wider font-display italic">Ingestion Pipeline Monitor</h3>
            </div>
            <div className="flex items-center gap-2">
              <button 
                onClick={onClearLogs}
                className="text-[10px] uppercase font-bold tracking-widest text-slate-450 hover:text-rose-400 hover:bg-[#1a1a1a] transition py-1.5 px-3 rounded-none border border-[#333] flex items-center gap-1.5 font-mono cursor-pointer"
              >
                <Trash2 className="h-3.5 w-3.5" />
                Flush Stream
              </button>
            </div>
          </div>

          {/* Table Header */}
          <div className="grid grid-cols-12 gap-2 text-[9px] font-bold text-slate-550 uppercase tracking-widest pb-2.5 border-b border-[#222]">
            <div className="col-span-2 font-mono">Timestamp</div>
            <div className="col-span-2 font-mono">Source IP</div>
            <div className="col-span-1 font-mono">Port</div>
            <div className="col-span-2 font-mono">Topic/Queue</div>
            <div className="col-span-1 font-mono">Method</div>
            <div className="col-span-3 font-mono">Target Asset / Payload</div>
            <div className="col-span-1 text-right font-mono">Entropy</div>
          </div>

          <div className="max-h-[310px] overflow-y-auto space-y-1 pt-2 pr-1 font-mono text-[11px]">
            {logs.length === 0 ? (
              <div className="text-center py-16 text-slate-600 font-mono text-xs">
                <Activity className="h-8 w-8 text-slate-805 mx-auto mb-2 animate-pulse" />
                Ingestion pipeline buffer empty. Activate generator stream or dispatch custom packets.
              </div>
            ) : (
              logs.slice(0, 100).map((log) => {
                const isMalicious = log.severity !== "Low";
                const isBlacklisted = blacklistedIps.has(log.sourceIp);
                return (
                  <div 
                    key={log.id} 
                    className={`grid grid-cols-12 gap-2 p-2 rounded-none border transition-colors ${
                      isBlacklisted 
                        ? "bg-[#1d120a] border-amber-900/30 text-amber-200" 
                        : isMalicious 
                          ? "bg-[#251011] border-[#FF2E2E]/10 text-rose-200" 
                          : "bg-[#050505]/40 border-[#222]/30 text-slate-300 hover:bg-[#111]"
                    }`}
                  >
                    <div className="col-span-2 text-slate-500 font-mono text-[10px] truncate">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </div>
                    
                    <div className="col-span-2 font-bold font-mono truncate flex items-center gap-1">
                      {log.sourceIp}
                      {isBlacklisted && <span className="text-[8px] bg-amber-500/10 text-amber-400 px-1 font-bold border border-amber-500/20">Banned</span>}
                    </div>

                    <div className="col-span-1 text-slate-400 font-mono">{log.targetPort}</div>

                    <div className="col-span-2 truncate">
                      <span className={`px-1.5 py-0.5 rounded-none text-[9px] font-bold uppercase tracking-wider font-mono border ${
                        log.topic === "auth-topic" 
                          ? "bg-blue-950/20 text-blue-300 border-blue-900/40" 
                          : log.topic === "web-access-topic"
                            ? "bg-violet-950/20 text-violet-300 border-violet-900/40"
                            : "bg-teal-950/20 text-teal-300 border-teal-900/40"
                      }`}>
                        {log.topic.replace("-topic", "")}
                      </span>
                    </div>

                    <div className="col-span-1 text-slate-400 font-extrabold text-[10px] font-mono">{log.method}</div>

                    <div className="col-span-3 truncate text-slate-200 font-mono" title={log.urlPath || log.payload}>
                      {log.urlPath || log.payload || log.command || "Unknown transaction log"}
                    </div>

                    <div className={`col-span-1 text-right font-mono font-bold ${
                      log.entropy > 5.2 ? "text-[#00F0FF]" : "text-slate-500"
                    }`}>
                      {log.entropy.toFixed(3)}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

      </div>

      {/* RIGHT SIDEBAR: Controls, Attack Injectors, Kafka Status */}
      <div className="space-y-6">

        {/* Integration Cluster Control */}
        <div className="bg-[#0D0D0D] border border-[#222] rounded-none p-5">
          <h3 className="text-sm font-black text-white font-display uppercase tracking-wider italic mb-3">Logs Stream Motor Control</h3>
          
          <div className="space-y-4">
            <div className="flex items-center justify-between font-mono text-[11px]">
              <span className="text-slate-400">Engine Core Telemetry</span>
              <span className={`px-2 py-0.5 rounded-none text-[9px] font-bold tracking-widest flex items-center gap-1 border ${
                isStreaming ? "bg-[#0b1b11] text-emerald-400 border-emerald-900/50 animate-pulse" : "bg-neutral-900 text-slate-500 border-neutral-800"
              }`}>
                <span className={`h-1.5 w-1.5 rounded-none ${isStreaming ? "bg-emerald-450" : "bg-slate-600"}`}></span>
                {isStreaming ? "STREAMING" : "HALTED"}
              </span>
            </div>

            <button 
              onClick={() => setIsStreaming(!isStreaming)}
              className={`w-full py-2.5 px-4 rounded-none font-bold text-xs uppercase tracking-wider font-mono flex items-center justify-center gap-2 transition duration-200 cursor-pointer ${
                isStreaming 
                  ? "bg-neutral-900 text-slate-350 hover:bg-neutral-850 border border-[#333]" 
                  : "bg-[#00F0FF] hover:bg-cyan-400 text-slate-950 font-black italic font-display"
              }`}
            >
              {isStreaming ? (
                <>
                  <Pause className="h-3.5 w-3.5" />
                  Halt Ingestion
                </>
              ) : (
                <>
                  <Play className="h-3.5 w-3.5 fill-slate-950" />
                  Resume pipeline
                </>
              )}
            </button>

            <div className="space-y-2">
              <div className="flex justify-between text-xs text-slate-500 font-mono">
                <span>Ingestion delay rate</span>
                <span className="font-bold text-[#00F0FF]">{speed} ms</span>
              </div>
              <input 
                type="range" 
                min={200}
                max={3000}
                step={100}
                value={speed}
                onChange={(e) => setSpeed(Number(e.target.value))}
                className="w-full accent-cyan-400 h-1 bg-neutral-900 cursor-pointer"
              />
              <div className="flex justify-between text-[8px] text-slate-600 font-bold uppercase tracking-wider font-mono">
                <span>Core Speed</span>
                <span>Audit Pace</span>
              </div>
            </div>
          </div>
        </div>

        {/* Live Attack Injection Simulator */}
        <div className="bg-[#0D0D0D] border border-[#222] rounded-none p-5">
          <div className="flex items-center gap-1.5 mb-3">
            <Zap className="h-4 w-4 text-[#FF2E2E]" />
            <h3 className="text-sm font-black text-white font-display uppercase tracking-wider italic">Payload Injection Deck</h3>
          </div>
          <p className="text-[11px] text-slate-500 font-mono leading-relaxed mb-4">
            Directly simulate known enterprise threat indices to test real-time signature matching and heuristics.
          </p>

          <div className="space-y-2">
            {ATTACK_BLUEPRINTS.map((blueprint, index) => (
              <button
                key={blueprint.name}
                onClick={() => onInjectAttack(index)}
                className="w-full text-left bg-[#050505] border border-[#222] hover:bg-neutral-900 hover:border-neutral-700 transition p-2.5 rounded-none text-slate-300 flex items-center justify-between cursor-pointer"
              >
                <div>
                  <div className="font-bold text-white text-[11px] font-mono tracking-tight uppercase">{blueprint.name}</div>
                  <div className="text-[9px] text-[#00F0FF] font-mono">Queue: {blueprint.topic.replace("-topic", "")} | Port: {blueprint.targetPort}</div>
                </div>
                <span className={`text-[8px] font-extrabold uppercase px-1.5 py-0.5 rounded-none font-mono border ${
                  blueprint.severity === "Critical" 
                    ? "bg-[#251011] border-[#FF2E2E]/40 text-[#FF2E2E]"
                    : blueprint.severity === "High" 
                      ? "bg-[#251011] border-[#FF2E2E]/20 text-[#FF2E2E]/80"
                      : "bg-[#1d120a] border-amber-900/30 text-amber-500"
                }`}>
                  {blueprint.severity}
                </span>
              </button>
            ))}
          </div>

          {/* Manual Log Ingestion Trigger */}
          <div className="mt-4 border-t border-[#222] pt-4">
            {!showManualForm ? (
              <button 
                onClick={() => setShowManualForm(true)}
                className="w-full text-center text-xs text-slate-400 hover:text-[#00F0FF] transition hover:bg-neutral-900 py-2.5 rounded-none border border-dashed border-[#333] uppercase font-mono tracking-wider cursor-pointer"
              >
                + Create custom event frame
              </button>
            ) : (
              <form onSubmit={handleManualSubmit} className="space-y-3.5 pt-1">
                <div>
                  <label className="block text-[9px] uppercase font-bold text-slate-500 mb-1 font-mono tracking-widest">Asset Target Endpoint</label>
                  <input 
                    type="text" 
                    value={manualUrl} 
                    onChange={e => setManualUrl(e.target.value)} 
                    className="w-full bg-[#050505] text-xs border border-[#222] rounded-none p-2 text-white font-mono focus:border-[#00F0FF] focus:outline-none"
                    placeholder="/api/login"
                  />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block text-[9px] uppercase font-bold text-slate-500 mb-1 font-mono tracking-widest">Target Port</label>
                    <input 
                      type="number" 
                      value={manualPort} 
                      onChange={e => setManualPort(Number(e.target.value))} 
                      className="w-full bg-[#050505] text-xs border border-[#222] rounded-none p-2 text-white font-mono focus:border-[#00F0FF] focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-[9px] uppercase font-bold text-slate-500 mb-1 font-mono tracking-widest">Method Type</label>
                    <span className="w-full bg-neutral-900 border border-[#222] rounded-none p-2 text-slate-400 block text-xs font-black font-mono">POST</span>
                  </div>
                </div>
                <div>
                  <label className="block text-[9px] uppercase font-bold text-slate-500 mb-1 font-mono tracking-widest">HTTP Headers (JSON)</label>
                  <input 
                    type="text" 
                    value={manualHeaders} 
                    onChange={e => setManualHeaders(e.target.value)} 
                    className="w-full bg-[#050505] text-xs border border-[#222] rounded-none p-2 text-white font-mono focus:border-[#00F0FF] focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-[9px] uppercase font-bold text-slate-500 mb-1 font-mono tracking-widest">Log Payload Stream</label>
                  <textarea 
                    value={manualPayload} 
                    onChange={e => setManualPayload(e.target.value)} 
                    rows={2}
                    className="w-full bg-[#050505] text-xs border border-[#222] rounded-none p-2 text-white font-mono focus:border-[#00F0FF] focus:outline-none"
                    placeholder='{"token": "xyz"}'
                  />
                </div>
                <div className="flex gap-2 justify-end font-mono">
                  <button 
                    type="button" 
                    onClick={() => setShowManualForm(false)}
                    className="text-xs text-slate-500 hover:text-white px-2 py-1 cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button 
                    type="submit" 
                    className="bg-[#00F0FF] hover:bg-cyan-400 text-[#050505] font-black italic uppercase font-display px-4 py-1.5 rounded-none transition cursor-pointer"
                  >
                    Inject Log
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>

        {/* Kafka Topics Partition Status */}
        <div className="bg-[#0D0D0D] border border-[#222] rounded-none p-5">
          <div className="flex items-center gap-1.5 mb-3">
            <Layers className="h-4 w-4 text-[#00F0FF]" />
            <h3 className="text-sm font-black text-white font-display uppercase tracking-wider italic">Kafka Topic Partitions</h3>
          </div>
          
          <div className="space-y-3">
            {kafkaStats.map((topic) => (
              <div key={topic.name} className="bg-[#050505] p-3.5 border border-[#222] rounded-none font-mono">
                <div className="flex justify-between items-center mb-1.5">
                  <span className="text-xs font-black text-white font-mono uppercase tracking-tight">{topic.name}</span>
                  <span className="text-[10px] text-slate-500">Lag: {topic.lag} frame</span>
                </div>
                <div className="flex justify-between text-[10px] text-slate-500">
                  <span>Partitions: {topic.partitions}</span>
                  <span className="text-right text-[#00F0FF] font-black">{topic.throughput} msgs/s</span>
                </div>
                {/* Visual partition locks indicator */}
                <div className="mt-2.5 grid grid-cols-8 gap-1">
                  {Array.from({ length: topic.partitions }).map((_, partIdx) => (
                    <div 
                      key={partIdx} 
                      className={`h-1.5 rounded-none ${
                        isStreaming 
                          ? Math.random() < 0.6 
                            ? "bg-[#00F0FF]" 
                            : "bg-[#00F0FF]/30" 
                          : "bg-[#222]"
                      }`}
                    />
                  ))}
                  {Array.from({ length: 8 - topic.partitions }).map((_, emptyIdx) => (
                    <div key={emptyIdx} className="h-1.5 rounded-none bg-neutral-900" />
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Alarm Threat Log Matrix */}
        <div className="bg-[#0D0D0D] border border-[#222] rounded-none p-5">
          <h3 className="text-xs font-black text-white uppercase tracking-wider font-display italic mb-3">Threat Profile Spectrum</h3>
          <div className="h-32 w-full">
            {alerts.length === 0 ? (
              <div className="text-center text-slate-600 text-xs font-mono py-10">No active categories classified.</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={categoryData}>
                  <XAxis dataKey="name" stroke="#444" fontSize={8} tickLine={false} fontClassName="font-mono" />
                  <Tooltip 
                    contentStyle={{ backgroundColor: "#070707", borderColor: "#222" }}
                  />
                  <Bar dataKey="Count" fill="#FF2E2E" radius={[0, 0, 0, 0]}>
                    {categoryData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={index % 2 === 0 ? "#FF2E2E" : "#00F0FF"} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

      </div>

    </div>
  );
}
