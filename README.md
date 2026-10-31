# isol8

An air-gapped AI agent security firewall and policy governance gateway powered by local Gemma 4 inference.

## Overview

As autonomous AI agents are granted access to execute system tools, browse files, and trigger outbound network requests, real-time security boundaries become necessary. isol8 acts as an interception gateway that sits between agent action proposals and actual execution environments.

Every proposed action (tool invocation, target file path, payload, and destination) is evaluated against active security policies before the operation is permitted to proceed.

## Event Details

- Event: Hacktoberfest X NavraCommunity
- Track / Topic: Best use case of Gemma 4

## Why Gemma 4 for Policy Governance

AI governance at the execution layer requires:
- Low latency: Decisions must occur synchronously before tool execution.
- Local, air-gapped execution: Sensitive code, database connection strings, and internal paths must never leave the local machine to reach external cloud APIs for evaluation.
- Structured reasoning: Gemma 4 reliably evaluates proposed operations against natural language policy rules, categorizes risk (LOW, MEDIUM, HIGH), and outputs strict JSON decisions (ALLOW, DENY, REQUIRE_APPROVAL).
- Deterministic hybrid guardrails: The system pairs Gemma 4's contextual reasoning with deterministic pattern matching to eliminate hallucination risks on critical assets (such as private keys and destructive commands).

## Architecture

The system consists of two primary modules:

1. Policy Firewall Backend (`policy-firewall-backend`):
   - Express.js gateway operating on port 5000.
   - Manages policy definitions, state toggling, and audit event logs.
   - Connects to local LM Studio running `google/gemma-4-e4b` for contextual action evaluation.
   - Incorporates hard fallback guardrails and pattern matching for offline resilience.

2. Operations Dashboard (`policy-firewall-dashboard-build`):
   - Next.js (App Router) and Tailwind CSS management interface.
   - SWR-driven live polling of policy statuses and decision audit streams.
   - Interactive Agent Action Simulator for dry-running tool calls.
   - Real-time approval workflow allowing human reviewers to approve or deny flagged actions.

## Repository Structure

```
isol8/
├── LICENSE                           # MIT License
├── README.md                         # Project documentation
├── policy-firewall-backend/          # Node.js governance gateway
│   ├── server.js                     # Policy engine and evaluation logic
│   └── package.json                  # Backend dependencies
│
└── policy-firewall-dashboard-build/  # Next.js operations interface
    ├── app/                          # Next.js App Router and styling
    ├── components/                   # Dashboard and UI primitives
    └── package.json                  # Frontend dependencies
```

## Getting Started

### Prerequisites

- Node.js (v18 or higher)
- pnpm or npm
- LM Studio (optional, for local Gemma 4 inference with model `google/gemma-4-e4b` on port 1234)

### 1. Backend Setup

```bash
cd policy-firewall-backend
npm install
node server.js
```

The gateway starts at `http://localhost:5000`. If LM Studio is not active, the gateway automatically uses deterministic rule-based evaluation.

### 2. Frontend Setup

```bash
cd policy-firewall-dashboard-build
pnpm install
pnpm dev
```

The dashboard will be available at `http://localhost:3000`.

## License

MIT
