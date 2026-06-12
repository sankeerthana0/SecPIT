export interface LogEntry {
  id: string;
  timestamp: string;
  sourceIp: string;
  targetPort: number;
  method: string;
  urlPath?: string;
  userAgent?: string;
  username?: string;
  command?: string;
  payload?: string;
  headers?: string;
  statusCode?: number;
  severity: "Low" | "Medium" | "High" | "Critical";
  topic: "auth-topic" | "web-access-topic" | "syslog-topic";
  entropy: number; // Shannon entropy calculated for request body or URL length
}

export type SeverityType = "Low" | "Medium" | "High" | "Critical";

export interface ThreatRule {
  id: string;
  ruleName: string;
  severity: SeverityType;
  category: string;
  description: string;
  pattern: string; // Regexp or match pattern
  targetField: "urlPath" | "payload" | "userAgent" | "username" | "command" | "headers";
  isEnabled: boolean;
  engineType: "Signature" | "ML-Anomaly";
  matchedTimes: number;
  recommendedMitigation?: string;
}

export interface AlertEntry {
  id: string;
  timestamp: string;
  ruleId: string;
  ruleName: string;
  sourceIp: string;
  targetPort: number;
  payload?: string;
  message: string;
  severity: SeverityType;
  engine: "Signature Core v2" | "ML isolation engine";
  status: "Unresolved" | "Acknowledged" | "Blocked";
  aiAnalysis?: AIAnalysisResult;
}

export interface AIAnalysisResult {
  summary: string;
  threatActorProfile: string;
  maliciousIntent: string;
  criticalityExplanation: string;
  mitigationActions: string[];
  remediationScript: string;
}

export interface KafkaTopicStats {
  name: string;
  throughput: number; // msgs/sec
  lag: number; // backlog size
  partitions: number;
}
