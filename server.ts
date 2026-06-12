import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json());

// Helper to check and retrieve Gemini Client
function getGeminiClient() {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    console.warn("GEMINI_API_KEY is not defined. AI features will fallback to template responses.");
    return null;
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      }
    }
  });
}

// API Route: AI-powered Threat Analysis
app.post("/api/analyze-threat", async (req, res) => {
  const { alert, correlativeLogs } = req.body;

  if (!alert) {
    return res.status(400).json({ error: "Missing required 'alert' field in request body." });
  }

  const ai = getGeminiClient();
  if (!ai) {
    // Elegant fallback mock response to maintain usability if API key is missing
    return res.json({
      summary: `Fallback Simulation: Analyzed suspicious traffic from IP ${alert.sourceIp} targeted at port ${alert.targetPort}. Detected signature '${alert.ruleName}'.`,
      threatActorProfile: "Likely automated scanning botnet or opportunistic attacker searching for exposed services.",
      maliciousIntent: "Enroute to mapping network vulnerabilities, brute-forcing weak service ports, or executing remote exploit payloads.",
      criticalityExplanation: `Severity is categorized as ${alert.severity}. Immediate risk is high due to the persistent traffic volume resembling signature ${alert.ruleName}. If successful, this could lead to unauthorized system access or service downtime.`,
      mitigationActions: [
        `Instantly block source IP ${alert.sourceIp} on system firewalls (iptables/UFW/AWS Security Group).`,
        `Inspect target server container metrics on port ${alert.targetPort} for active sessions or unauthorized state changes.`,
        `Cross-examine authentication logs for successful login confirmations following this failure spike.`,
        "Temporarily quarantine host container to prevent lateral movement."
      ],
      remediationScript: `# Automated Isolation Sequence\niptables -A INPUT -s ${alert.sourceIp} -j DROP\n# Kill active socket connections\ntcpkill -9 host ${alert.sourceIp} 2>/dev/null || true\n# Log containment event\necho "$(date) - BLOCKED ${alert.sourceIp} - Threat: ${alert.ruleName}" >> /var/log/threat_remediation.log\necho "Host isolated successfully."`
    });
  }

  try {
    const logExcerpt = Array.isArray(correlativeLogs) 
      ? correlativeLogs.slice(0, 10).map(l => JSON.stringify(l)).join("\n") 
      : "No correlative log stream provided.";

    const prompt = `You are an elite, automated Security Operations Center (SOC) incident responder.
Analyze this high-severity alert triggered by your modular threat detection engine (Kafka streaming logs pipeline).

[ALERT DETAILS]
ID: ${alert.id}
Timestamp: ${alert.timestamp}
Signature/Rule Triggered: ${alert.ruleName}
Source Host IP: ${alert.sourceIp}
Destination Service Port: ${alert.targetPort}
Engine Method: ${alert.engine}
Severity Level: ${alert.severity}
Alert Message: ${alert.message}
Trigger Payload: ${JSON.stringify(alert.payload || '')}

[CORRELATED LOG EXCERPTS FROM SAME ENTITY]
${logExcerpt}

Assess the payload and logs meticulously. Formulate an advanced cyber threat report that includes:
1. Executive Summary: What precisely occurred and what is the current situation.
2. Threat Actor Profile: What kind of actor is this (advanced persistent threat, automated script, script kiddie, scanner)?
3. Malicious Intent: What is their end-goal based on the payload (e.g. directory traversal, remote code execution, DDoS, injection)?
4. Criticality Explanation: Why is this categorized as ${alert.severity}, and what happens if left unmitigated?
5. Mitigation Actions: A list of 4 concrete, actionable containment guidelines.
6. Remediation Script: A professional, production-ready Unix Bash or firewall script that blocks the attacker, terminates the connection socket, or isolates the container safely. Include security comments inside the script.`;

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: prompt,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            summary: { 
              type: Type.STRING, 
              description: "A professional executive summary of the security incident (2-3 sentences)." 
            },
            threatActorProfile: { 
              type: Type.STRING, 
              description: "Probable tier or type of the threat actor involved." 
            },
            maliciousIntent: { 
              type: Type.STRING, 
              description: "The specific objective or targeted impact of the attack (e.g., Remote Code Execution, Privilege Escalation)." 
            },
            criticalityExplanation: { 
              type: Type.STRING, 
              description: "Detailed context on the impact score, threat speed, and risks of delayed action." 
            },
            mitigationActions: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: "List of 4 distinct operational containment actions for security personnel."
            },
            remediationScript: { 
              type: Type.STRING, 
              description: "Actionable Unix shell script, docker-cli command sequence, or firewall blocking sequence containing inline comments." 
            }
          },
          required: ["summary", "threatActorProfile", "maliciousIntent", "criticalityExplanation", "mitigationActions", "remediationScript"]
        }
      }
    });

    const data = JSON.parse(response.text?.trim() || "{}");
    return res.json(data);
  } catch (error: any) {
    console.error("Gemini Threat Analysis Error:", error);
    return res.status(500).json({ 
      error: "Failed to generate AI threat analysis.", 
      details: error.message 
    });
  }
});

// API Route: Custom Attack Rules/Signature Generator
app.post("/api/generate-signature", async (req, res) => {
  const { attackDescription } = req.body;

  if (!attackDescription) {
    return res.status(400).json({ error: "Missing required 'attackDescription' field in request body." });
  }

  const ai = getGeminiClient();
  if (!ai) {
    // Fallback Mock Rule Generation
    return res.json({
      ruleName: "Manual Attack Signature",
      severity: "High",
      category: "Intrusion",
      description: `Signature generated dynamically for: ${attackDescription}`,
      pattern: "/etc/passwd|cmd\\.exe|UNION|SELECT",
      targetField: "urlPath",
      recommendedMitigation: "Enforce web application firewall patterns and check server access bounds."
    });
  }

  try {
    const prompt = `You are a Principal Security Rule Engineer.
The user wants to write a signature detection rule for our real-time logs parsing modular engine.
Here is the description of the cyber attack vector, technique, or vulnerability they wish to detect:
"${attackDescription}"

Formulate a clean JSON object representing a concrete signature rule.
The rule will contain:
1. ruleName: A concise snake_case identifier (e.g. sql_injection_attempt, log4j_jndi_exploit)
2. severity: Severity level (Critical, High, Medium, or Low)
3. category: The security tier (e.g., Exfiltration, Injection, Auth Bypass, Denial of Service, Scanner)
4. description: A helpful summary of what this signature attempts to capture.
5. pattern: A standard regular expression pattern (or search string) matching the malicious token in logs (e.g., "(?i)union\\s+select" or "(?i)\\.\\./\\.\\."). Keep it clean and valid JSON.
6. targetField: The log field string to scan (must be one of: 'urlPath', 'payload', 'userAgent', 'username', 'command', 'headers').
7. recommendedMitigation: Tailored automated response rule details (WAF blockage, IP ban, etc.)`;

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: prompt,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            ruleName: { type: Type.STRING },
            severity: { type: Type.STRING },
            category: { type: Type.STRING },
            description: { type: Type.STRING },
            pattern: { type: Type.STRING, description: "A valid regex string without escaping issues" },
            targetField: { type: Type.STRING },
            recommendedMitigation: { type: Type.STRING }
          },
          required: ["ruleName", "severity", "category", "description", "pattern", "targetField", "recommendedMitigation"]
        }
      }
    });

    const ruleData = JSON.parse(response.text?.trim() || "{}");
    return res.json(ruleData);
  } catch (error: any) {
    console.error("Gemini Signature Generation Error:", error);
    return res.status(500).json({ 
      error: "Failed to generate AI signature rule.", 
      details: error.message 
    });
  }
});

// Vite & Static file handling integration
async function main() {
  if (process.env.NODE_ENV !== "production") {
    console.log("Starting server in DEVELOPMENT mode with Vite Middleware...");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    console.log("Starting server in PRODUCTION mode...");
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Threat Detection Platform running on http://0.0.0.0:${PORT}`);
  });
}

main().catch((err) => {
  console.error("Failed to boot Threat Detection Platform Express server:", err);
});
