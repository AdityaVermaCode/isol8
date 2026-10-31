const express = require('express');
const cors = require('cors');

const app = express();

// 1. Full CORS enablement for local Next.js origins
app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type'],
    credentials: true
}));

app.use(express.json());

// Endpoint for local LM Studio instance
const LM_STUDIO_URL = 'http://127.0.0.1:1234/v1/chat/completions';

// 2. State-managed active security policies matching UI structure
let activePolicies = [
    {
        id: "p1",
        name: "Secrets stay local",
        clause: "Deny reads of .env, credentials, and private keys",
        enabled: true,
        tone: "rose"
    },
    {
        id: "p2",
        name: "Workspace read access",
        clause: "Allow read-only access to project documentation and source code",
        enabled: true,
        tone: "emerald"
    },
    {
        id: "p3",
        name: "PII egress review",
        clause: "Require approval before personal data leaves the workspace",
        enabled: true,
        tone: "amber"
    },
    {
        id: "p4",
        name: "External destinations",
        clause: "Review outbound requests to untrusted destinations",
        enabled: true,
        tone: "cyan"
    }
];

// Audit log history store
let decisionLogs = [];

// GET Active Policies
app.get('/api/policies', (req, res) => {
    res.json({ success: true, policies: activePolicies });
});

// POST Add Custom Policy
app.post('/api/policies', (req, res) => {
    const { policy, name, clause } = req.body;
    const policyName = name || policy;

    if (policyName && policyName.trim()) {
        const newPolicy = {
            id: `p-${Date.now()}`,
            name: policyName.trim(),
            clause: clause || "Custom policy added via governance console",
            enabled: true,
            tone: "cyan"
        };
        activePolicies.unshift(newPolicy);
    }
    res.json({ success: true, policies: activePolicies });
});

// PUT Toggle Policy On/Off State
app.put('/api/policies/:id/toggle', (req, res) => {
    const { id } = req.params;
    const target = activePolicies.find(p => p.id === id);
    if (target) {
        target.enabled = !target.enabled;
    }
    res.json({ success: true, policies: activePolicies });
});

// GET Decision Audit Logs
app.get('/api/logs', (req, res) => {
    res.json({ success: true, logs: decisionLogs });
});

// POST Human Reviewer Resolution (Approve / Deny)
app.post('/api/resolve', (req, res) => {
    const { id, decision } = req.body;
    const targetLog = decisionLogs.find(l => l.id === id);
    if (targetLog) {
        targetLog.decision = decision === 'APPROVED' ? 'ALLOW' : 'DENY';
        targetLog.reasoning = `Human operator manually ${decision.toLowerCase()} this action request.`;
    }
    res.json({ success: true, logs: decisionLogs });
});

// POST Evaluate Action (Gemma 4 Gateway)
app.post('/api/evaluate', async (req, res) => {
    const { tool, path: filePath, payload, destination } = req.body;

    const actionTool = (tool || 'fs.read').trim();
    const actionPath = (filePath || '/workspace/README.md').trim();
    const actionPayload = (payload || '').trim();
    const actionDestination = (destination || 'local workspace').trim();

    const fullText = `${actionTool} ${actionPath} ${actionPayload} ${actionDestination}`.toLowerCase();

    // Filter only enabled policies for evaluation
    const enabledRules = activePolicies.filter(p => p.enabled);

    // Strict Security Threat Patterns
    const isSecret = /\.env|\.yml|\.yaml|\.pem|credential|private.?key|secret|database|password|auth_token|api_key/i.test(fullText);
    const isDestructive = /rm\s+-rf|drop\s+table|delete|format|kill|exec|bash/i.test(fullText);
    const isPii = /pii|customer|email|personal|account_id|full_name|ssn/i.test(fullText) &&
        (/https?:|external|vendor|export|upload|post/i.test(fullText) || !actionDestination.toLowerCase().includes('local'));

    const systemPrompt = `You are "Policy Firewall", an air-gapped security governance agent.
Evaluate the proposed action against these enabled active policies:
${enabledRules.map((p, i) => `${i + 1}. ${p.name}: ${p.clause}`).join('\n')}

DO NOT THINK OUT LOUD. Output ONLY raw JSON matching this schema:
{
    "decision": "ALLOW" | "DENY" | "REQUIRE_APPROVAL",
    "risk": "LOW" | "MEDIUM" | "HIGH",
    "policy": "Exact matched policy name",
    "reasoning": "1-sentence concise explanation."
}`;

    const userPrompt = JSON.stringify({
        tool: actionTool,
        path: actionPath,
        payload: actionPayload,
        destination: actionDestination
    });

    try {
        const lmResponse = await fetch(LM_STUDIO_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                model: 'google/gemma-4-e4b',
                messages: [
                    { role: 'system', content: systemPrompt },
                    { role: 'user', content: userPrompt }
                ],
                temperature: 0.0,
                max_tokens: 150
            })
        });

        const data = await lmResponse.json();
        const rawContent = data.choices[0].message.content.trim();
        const cleanedJson = rawContent.replace(/```json|```/g, '').trim();
        let evaluation = JSON.parse(cleanedJson);

        // Hard Override Guardrail to catch LLM hallucinations on critical threats
        if (isSecret || isDestructive) {
            evaluation.decision = "DENY";
            evaluation.risk = "HIGH";
            evaluation.policy = "Secrets stay local";
            evaluation.reasoning = "Secret files, credentials, or dangerous shell execution commands are strictly prohibited.";
        } else if (isPii) {
            evaluation.decision = "REQUIRE_APPROVAL";
            evaluation.risk = "HIGH";
            evaluation.policy = "PII egress review";
            evaluation.reasoning = "Outbound transfer containing identifiable user data requires human reviewer approval.";
        }

        const logEntry = {
            id: `evt-${Date.now()}`,
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
            risk: evaluation.risk || "MEDIUM",
            decision: evaluation.decision || "ALLOW",
            tool: actionTool,
            path: actionPath,
            payload: actionPayload,
            destination: actionDestination,
            reasoning: evaluation.reasoning || "Evaluation processed by air-gapped governance engine.",
            policy: evaluation.policy || "Workspace read access"
        };

        decisionLogs.unshift(logEntry);
        return res.json({ success: true, evaluation, log: logEntry });

    } catch (error) {
        // Deterministic Fallback Evaluator when LM Studio is offline
        let decision = "ALLOW";
        let risk = "LOW";
        let policy = "Workspace read access";
        let reasoning = "The agent is executing standard workspace operations within policy boundaries.";

        if (isSecret || isDestructive) {
            decision = "DENY";
            risk = "HIGH";
            policy = "Secrets stay local";
            reasoning = "Blocked access to sensitive credential configurations, private keys, or shell commands.";
        } else if (isPii) {
            decision = "REQUIRE_APPROVAL";
            risk = "HIGH";
            policy = "PII egress review";
            reasoning = "Outbound transfer containing personal customer data requires human review.";
        } else if (/http|write|delete|exec/i.test(actionTool)) {
            risk = "MEDIUM";
        }

        const fallbackEval = { decision, risk, policy, reasoning };
        const logEntry = {
            id: `evt-${Date.now()}`,
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
            risk,
            decision,
            tool: actionTool,
            path: actionPath,
            payload: actionPayload,
            destination: actionDestination,
            reasoning,
            policy
        };

        decisionLogs.unshift(logEntry);
        return res.json({ success: true, evaluation: fallbackEval, log: logEntry });
    }
});

// Bind to 0.0.0.0 to resolve local IPv4/IPv6 address binding conflicts
app.listen(5000, '0.0.0.0', () => {
    console.log('Policy Firewall Gateway running on http://localhost:5000');
});