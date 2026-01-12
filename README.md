# Autonomous Vulnerability Triage Agent

An agentic AI workflow that operationalizes offensive intelligence. It ingests the CISA KEV catalog, autonomously hunts for Proof-of-Concept (PoC) exploits using Tavily, and generates actionable triage reports validated by a Critic agent.

## 🚀 The Mission
Security analysts waste hours validating if a High Severity CVE actually has a public exploit. This agent automates that specific question: **"Is there a weaponized PoC for this threat?"**

## 🏗️ Architecture
**Sense** $\to$ **Think** $\to$ **Act**
1.  **Ingest:** Async fetching of the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog.
2.  **Research:** A `GPT-5-Mini` Analyst uses the **Tavily API** to specifically hunt for GitHub repos and ExploitDB entries.
3.  **Quality Gate:** A **Critic Agent** (No Internet) reviews drafts for specificity. Generic "Apply Patch" advice is REJECTED.
4.  **Validation:** A deterministic Python validator enforces a strict Markdown schema before output.

## 🛠️ Tech Stack
* **AI:** OpenAI Agents SDK (GPT-5-Mini)
* **Search:** Tavily API (Optimized for raw JSON context)
* **State:** Local JSON (Stateless/Portable)
* **Language:** Python 3.12+

## ⚡ Quick Start

1. **Clone the repo**
   ```bash
   git clone https://github.com/yourusername/autonomous-triage-agent.git
   ```
2. **Install dependencies**
   ```bash
   pip install -r requirements.txt

3. **Configure API Keys** Copy the example environment file:
   ``` bash
   cp .env.example .env
Add your keys to the new `.env` file:
* `OPENAI_API_KEY`
* `TAVILY_API_KEY`

4. **Run the Triage Agent**
```bash
python triage_report_agent.py
