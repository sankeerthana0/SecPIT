import React, { useState } from "react";
import { LogEntry } from "../types";
import { Search, Info, Sliders, Calendar, Terminal, Database, HelpCircle } from "lucide-react";

interface ExplorerTabProps {
  logs: LogEntry[];
}

export default function ExplorerTab({ logs }: ExplorerTabProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
  
  // Parse search criteria
  const performSearch = (logList: LogEntry[]): LogEntry[] => {
    if (!searchQuery.trim()) return logList;

    const query = searchQuery.trim().toLowerCase();
    
    // Check if user is using simple key-value search (e.g. `ip:198` or `port:22` or `severity:high`)
    if (query.includes(":")) {
      const parts = query.split(":");
      const searchKey = parts[0].trim();
      const searchVal = parts.slice(1).join(":").trim(); // support multiple colons just in case

      return logList.filter(l => {
        if (searchKey === "ip") {
          return l.sourceIp.toLowerCase().includes(searchVal);
        }
        if (searchKey === "port") {
          return String(l.targetPort).includes(searchVal);
        }
        if (searchKey === "severity") {
          return l.severity.toLowerCase() === searchVal;
        }
        if (searchKey === "topic") {
          return l.topic.toLowerCase().includes(searchVal);
        }
        if (searchKey === "status" || searchKey === "code") {
          return String(l.statusCode).includes(searchVal);
        }
        if (searchKey === "method") {
          return l.method.toLowerCase().includes(searchVal);
        }
        if (searchKey === "username" || searchKey === "user") {
          return String(l.username || "").toLowerCase().includes(searchVal);
        }
        // Fallback to searching any keys match values
        const objVal = String((l as any)[searchKey] || "");
        return objVal.toLowerCase().includes(searchVal);
      });
    }

    // Otherwise, do loose global search on any properties
    return logList.filter(l => {
      return (
        l.sourceIp.toLowerCase().includes(query) ||
        String(l.targetPort).includes(query) ||
        l.topic.toLowerCase().includes(query) ||
        l.method.toLowerCase().includes(query) ||
        String(l.urlPath || "").toLowerCase().includes(query) ||
        String(l.payload || "").toLowerCase().includes(query) ||
        String(l.command || "").toLowerCase().includes(query) ||
        String(l.username || "").toLowerCase().includes(query) ||
        l.severity.toLowerCase().includes(query)
      );
    });
  };

  const filteredLogs = performSearch(logs);

  return (
    <div className="space-y-6" id="explorer_tab_root">
      
      {/* SEARCH CARD INPUT */}
      <div className="bg-[#0D0D0D] border border-[#222] rounded-none p-6">
        <div className="flex items-center gap-1.5 mb-2.5">
          <Database className="h-4.5 w-4.5 text-[#00F0FF]" />
          <h3 className="text-sm font-black text-white font-display uppercase tracking-wider italic">Elastic Stack (Kibana Index Probing)</h3>
        </div>
        <p className="text-[11px] text-slate-500 font-mono mb-4">
          Query indexed logs instantaneously. Supports freeform text scan or key-value constraints (e.g. <code className="text-[#00F0FF] font-black">ip:198.51</code>, <code className="text-[#00F0FF] font-black">port:22</code>, <code className="text-[#00F0FF] font-black">severity:critical</code>, or <code className="text-[#00F0FF] font-black">status:401</code>).
        </p>

        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500 pointer-events-none" />
            <input 
              type="text" 
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search index eg: ip:198.51.100.42 or keyword: union select..."
              className="w-full bg-[#050505] text-xs border border-[#222] rounded-none py-3 pl-10 pr-4 text-white focus:border-[#00F0FF] focus:outline-none font-mono"
            />
          </div>
          
          <div className="flex gap-2 shrink-0 font-mono">
            <button 
              onClick={() => setSearchQuery("severity:critical")}
              className="px-3.5 py-2.5 text-[10px] uppercase font-bold bg-[#1a0f10] border border-[#FF2E2E]/25 hover:bg-rose-950/40 text-[#FF2E2E] rounded-none transition duration-150 cursor-pointer"
            >
              severity:critical
            </button>
            <button 
              onClick={() => setSearchQuery("port:22")}
              className="px-3.5 py-2.5 text-[10px] uppercase font-bold bg-neutral-900 border border-[#222] hover:bg-neutral-850 text-slate-350 rounded-none transition duration-150 cursor-pointer"
            >
              port:22
            </button>
            <button 
              onClick={() => setSearchQuery("")}
              className="px-3.5 py-2.5 text-[10px] uppercase font-bold border border-[#222] hover:border-[#444] text-slate-500 hover:text-white rounded-none transition duration-150 cursor-pointer"
            >
              Reset Query
            </button>
          </div>
        </div>
      </div>

      {/* THREE PANELS LAYOUT */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* MATCH RANGE AND LIST (COL 1 to 7) */}
        <div className="lg:col-span-7 bg-[#0D0D0D] border border-[#222] rounded-none p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-[#222] pb-3">
            <span className="text-xs font-bold text-slate-500 flex items-center gap-1.5 font-mono uppercase tracking-wider">
              <span>Lucene matches: </span>
              <span className="text-[#00F0FF] font-black">{filteredLogs.length}</span>
              <span className="text-slate-700">/ indexed total: {logs.length}</span>
            </span>
          </div>

          <div className="max-h-[500px] overflow-y-auto space-y-2 pr-1">
            {filteredLogs.length === 0 ? (
              <div className="text-center py-16 text-slate-600 font-mono text-xs">
                No matching indexes found in the active Kafka log pipeline database.
              </div>
            ) : (
              filteredLogs.map((log) => (
                <div 
                  key={log.id}
                  onClick={() => setSelectedLog(log)}
                  className={`p-3.5 rounded-none border text-left cursor-pointer transition font-mono text-[11px] ${
                    selectedLog?.id === log.id 
                      ? "bg-[#111111] border-[#00F0FF]" 
                      : log.severity !== "Low"
                        ? "bg-[#251011]/25 border-[#FF2E2E]/10 hover:bg-[#251011]/50"
                        : "bg-[#050505] border-[#222]/65 hover:bg-[#111]"
                  }`}
                >
                  <div className="flex justify-between items-center text-[9px] text-slate-500 mb-2 select-none uppercase tracking-wider font-bold">
                    <span className="flex items-center gap-1">
                      <Calendar className="h-3.5 w-3.5 text-slate-600" />
                      {new Date(log.timestamp).toISOString()}
                    </span>
                    <span className={`px-1.5 py-0.2 rounded-none font-mono font-black border ${
                      log.severity === "Critical" 
                        ? "bg-[#251011] border-[#FF2E2E]/40 text-[#FF2E2E]" 
                        : log.severity === "High" 
                          ? "bg-[#251011] border-[#FF2E2E]/20 text-[#FF2E2E]/80" 
                          : log.severity === "Medium"
                            ? "bg-[#1d120a] border-amber-900/30 text-amber-500"
                            : "bg-neutral-900 border-neutral-800 text-slate-500"
                    }`}>
                      {log.severity}
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1 mb-2.5">
                    <span className="text-white font-extrabold">{log.sourceIp}</span>
                    <span className="text-slate-700">→</span>
                    <span className="text-slate-400">dstPort: <span className="text-[#00F0FF] font-bold">{log.targetPort}</span></span>
                    <span className="text-[#333] border-l border-[#222] pl-2">topic: <span className="text-violet-400 font-bold uppercase text-[10px]">{log.topic.replace("-topic", "")}</span></span>
                  </div>

                  <div className="text-[11px] text-slate-350 truncate bg-[#050505] p-2 rounded-none border border-[#222]/80">
                    <span className="text-[#00F0FF] font-black mr-1.5 uppercase text-[10px]">{log.method}</span>
                    {log.urlPath || log.payload || log.command}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* LOG DETAILS IN-DEPTH INSPECTION (COL 8 to 12) */}
        <div className="lg:col-span-5 bg-[#0D0D0D] border border-[#222] rounded-none p-6 flex flex-col">
          <div className="flex items-center gap-1.5 mb-4 pb-3 border-b border-[#222] select-none">
            <Terminal className="h-4 w-4 text-[#00F0FF]" />
            <h3 className="text-sm font-black text-white font-display uppercase tracking-wider italic">Index Document Inspector</h3>
          </div>

          {!selectedLog ? (
            <div className="flex-1 flex flex-col items-center justify-center text-center py-16 text-slate-600 font-mono text-xs">
              <HelpCircle className="h-10 w-10 text-neutral-800 mb-2" />
              Click any log profile left to dump the Elastic search document source schema.
            </div>
          ) : (
            <div className="flex-1 space-y-4 text-xs font-mono">
              <div className="flex justify-between items-center bg-[#050505] p-3.5 border border-[#222] rounded-none">
                <div>
                  <div className="text-[8px] text-slate-500 font-bold uppercase tracking-widest font-mono mb-1">Document ID</div>
                  <div className="text-white font-black truncate max-w-[150px]">{selectedLog.id}</div>
                </div>
                <div className="text-right">
                  <div className="text-[8px] text-slate-500 font-bold uppercase tracking-widest font-mono mb-1">Entropy Index</div>
                  <div className="text-[#00F0FF] font-black text-sm">{selectedLog.entropy.toFixed(3)}</div>
                </div>
              </div>

              <div className="space-y-3 max-h-[350px] overflow-y-auto pr-1">
                <div>
                  <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-widest mb-1 font-mono">Timestamp (UTC)</span>
                  <span className="text-slate-350 block bg-[#050505] p-2 rounded-none border border-[#222] select-all leading-normal font-mono">{selectedLog.timestamp}</span>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-widest mb-1 font-mono">Source Host IP</span>
                    <span className="text-slate-250 block bg-[#050505] p-2 rounded-none border border-[#222] font-black text-[#00F0FF] select-all font-mono">{selectedLog.sourceIp}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-widest mb-1 font-mono">Target Port</span>
                    <span className="text-slate-250 block bg-[#050505] p-2 rounded-none border border-[#222] select-all font-mono">{selectedLog.targetPort}</span>
                  </div>
                </div>

                <div>
                  <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-widest mb-1 font-mono">Service Method ID</span>
                  <span className="text-slate-250 block bg-[#050505] p-2 rounded-none border border-[#222] font-semibold select-all font-mono">{selectedLog.method}</span>
                </div>

                {selectedLog.urlPath && (
                  <div>
                    <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-widest mb-1 font-mono font-mono">Requested URL Path</span>
                    <span className="text-cyan-200 block bg-[#050505] p-2 rounded-none border border-[#222] break-all select-all font-mono">{selectedLog.urlPath}</span>
                  </div>
                )}

                {selectedLog.username && (
                  <div>
                    <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-widest mb-1 font-mono">Auth Username attempt</span>
                    <span className="text-rose-300 block bg-[#050505] p-2 rounded-none border border-[#FF2E2E]/20 font-black select-all font-mono">{selectedLog.username}</span>
                  </div>
                )}

                {selectedLog.command && (
                  <div>
                    <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-widest mb-1 font-mono">Executed Shell Command</span>
                    <span className="text-[#00F0FF] block bg-[#050505] p-2 rounded-none border border-[#222] break-all select-all font-mono">{selectedLog.command}</span>
                  </div>
                )}

                {selectedLog.payload && (
                  <div>
                    <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-widest mb-1 font-mono">Transaction Payload</span>
                    <span className="text-amber-300 block bg-[#050505] p-2 rounded-none border border-[#222] break-all select-all font-mono">{selectedLog.payload}</span>
                  </div>
                )}

                {selectedLog.headers && (
                  <div>
                    <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-widest mb-1 font-mono font-mono">HTTP Headers Payload</span>
                    <pre className="text-slate-400 block bg-[#050505] p-2 rounded-none border border-[#222] text-[10px] overflow-x-auto select-all leading-relaxed font-mono">{selectedLog.headers}</pre>
                  </div>
                )}
              </div>

              {/* RAW JSON SCHEMA COMPILER DUMP */}
              <div className="pt-2">
                <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-widest mb-1.5 font-mono select-none">Raw Elastic Document Source</span>
                <textarea 
                  readOnly 
                  value={JSON.stringify(selectedLog, null, 2)}
                  rows={4}
                  className="w-full bg-[#050505] text-[10px] border border-[#222] rounded-none p-2.5 text-slate-500 font-mono resize-none focus:outline-none"
                />
              </div>
            </div>
          )}
        </div>

      </div>

    </div>
  );
}
