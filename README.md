<p align="center">
  <img src="assets/gliard_logo.svg" width="320" alt="Gliard Logo">
  <br>
  <i>"Building trust in the age of autonomous agents."</i>
</p>

# Gliard: The Advanced AI Agent Audit

Gliard is a professional-grade security auditor with deep analysis for Python agents and universal adversary simulation via HTTP. It addresses the unique risks of agentic workflows—from prompt injections and excessive agency to regulatory compliance.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Capabilities

Gliard provides a multi-layered defense strategy for production-ready AI agents:

- **Guard Engine (Core Product)**: Deep AST (Abstract Syntax Tree) logic analysis, robust reporting, and EU AI Act compliance mapping. Over 20 deterministic scanners providing highly stable and actionable insights.
- **Sentinel Engine (Beta)**: Experimental automated red teaming that verifies exploits in a simulated environment. Provided as an early-access bonus to Guard users.
- **EU AI Act Mapping**: Direct correlation of technical vulnerabilities to regulatory articles.
- **Board-Ready Reporting**: Beautiful PDF and console outputs designed for both developers and C-level executives.

---

## Quick Start

1. **Install from Archive**
   Download and extract the Gliard archive from LemonSqueezy, then run:
   ```bash
   pip install gliard_v1.0.0.tar.gz
   ```

2. **Run Audit**
   Run the interactive dashboard:
   ```bash
   gliard
   ```
   Or run a direct audit by passing the agent path:
   ```bash
   gliard /path/to/your/agent
   ```

> [!NOTE]
> Gliard is currently optimized for agents written in **Python**. While many security and prompt-based scanners are language-agnostic, the deep logic and simulation engines require a Python environment.

---

## Sentinel: Automated Red Teaming (Beta)

Gliard includes experimental access to the **Sentinel Engine**, simulating real-world attack vectors against agent code:

- Local API mocking to intercept agent tool calls.
- Payload injection directly into the LLM context window.
- Verification of RCE and unauthorized filesystem access.

> **Note:** Because LLMs are highly unpredictable, Sentinel is currently in **Beta**. We are constantly updating its payloads, response parsers, and marker systems to handle new edge cases and reduce false positives. The **Guard Engine** remains the deterministic core of the product.

---

## Compliance & Governance

Gliard automatically audits for **EU AI Act** requirements:
- **Transparency**: Article 13 compliance and user notification logic.
- **Oversight**: Article 14 human-in-the-loop verification.
- **Data Governance**: Article 10 management of training and input data.
- **Risk Management**: Article 9 continuous risk assessment.

---

## Professional Reporting

Gliard generates board-ready technical and strategic documentation:
- **Audit Report**: Technical deep-dive into every identified vulnerability.
- **Strategy Guide**: Step-by-step remediation instructions for technical teams.
- **Executive Summary**: High-level risk assessment for management stakeholders.
