import asyncio
import json
import os
import httpx
from datetime import datetime, timedelta
from typing import List, Dict, Set, Optional, Any
from dotenv import load_dotenv

# SDK Imports
from tavily import TavilyClient
from agents import Agent, Runner, function_tool

load_dotenv()

# --- CONFIGURATION ---
CISA_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MODEL_ID = "gpt-5-mini"
STATE_FILE = "processed_cves.json"
BATCH_SIZE = 3  # Configurable batch size for throttling


# --- PERSISTENCE LAYER ---
def load_processed_cves() -> Set[str]:
    """Loads the state of previously triaged CVEs to avoid duplicate work."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return set(json.load(f))
        except json.JSONDecodeError:
            return set()
    return set()


def save_processed_cve(cve_id: str) -> None:
    """Updates the state file atomically after successful processing."""
    processed = load_processed_cves()
    processed.add(cve_id)
    with open(STATE_FILE, "w") as f:
        json.dump(list(processed), f)


# --- DETERMINISTIC GUARDRAILS (The "Compiler") ---
def validate_report_structure(text: str) -> Optional[str]:
    """
    Validates that the AI-generated report adheres to the strict Markdown schema.
    Returns an error string if the structure is invalid, enabling the self-healing loop.
    """
    errors = []

    # 1. Check for Title Header
    if "##" not in text and "# " not in text:
        errors.append("Missing the CVE Title (must start with ## or #).")

    # 2. Check for Required Schema Sections
    required_sections = ["Severity", "Summary", "In the Wild", "Action"]
    for section in required_sections:
        if f"**{section}**" not in text and f"## {section}" not in text:
            errors.append(f"Missing required section: '{section}'")

    if errors:
        return "Validation Failed: " + " ".join(errors)
    return None


# --- ASYNC SENSE LAYER ---
async def pull_cisa_catalog() -> List[Dict[str, Any]]:
    """Fetches the official CISA KEV catalog asynchronously."""
    print(f"[*] SENSE: Connecting to CISA feed...")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(CISA_JSON_URL, timeout=10.0)
            response.raise_for_status()
            return response.json().get("vulnerabilities", [])
    except Exception as e:
        print(f"[-] Network Error: {e}")
        return []


def filter_active_threats(kev_list: List[Dict], days_back: int = 30) -> List[Dict]:
    """Filters for fresh CVEs that have not been persisted in state."""
    cutoff_date = datetime.now() - timedelta(days=days_back)
    processed_cves = load_processed_cves()
    active_threats = []

    for threat in kev_list:
        cve_id = threat.get("cveID")

        # Pipeline Logic: Skip known threats (Queue System)
        if cve_id in processed_cves:
            continue

        try:
            added_date = datetime.strptime(threat.get("dateAdded"), "%Y-%m-%d")
            if added_date > cutoff_date:
                active_threats.append(threat)
        except ValueError:
            continue

    return sorted(active_threats, key=lambda x: x["dateAdded"], reverse=True)


# --- ASYNC ACT LAYER (Tooling) ---
@function_tool
async def gather_threat_intel(cve_id: str) -> str:
    """
    Tool: Performs a semantic search for technical details using Tavily.
    Executes in a thread to prevent blocking the async event loop.
    """
    print(f"[*] TOOL: Searching context for {cve_id}...")
    api_key = os.getenv("TAVILY_API_KEY")
    if not api_key:
        return "Error: TAVILY_API_KEY not found in .env"

    try:
        tavily = TavilyClient(api_key=api_key)
        # Offload blocking I/O to a thread
        response = await asyncio.to_thread(
            tavily.search,
            query=f"{cve_id} exploit analysis technical details",
            search_depth="basic",
            max_results=3
        )
        context = response.get("results", [])
        return json.dumps(context) if context else "No external context found."

    except Exception as e:
        return f"Search Error: {e}"


# --- DECISION LAYER (Agent Architecture) ---

# Agent 1: The Researcher (Drafts the content)
analyst_agent = Agent(
    name="CISA_Researcher",
    model=MODEL_ID,
    instructions="""
    You are a Senior Vulnerability Analyst.
    PROTOCOL:
    1. Analyze the input CISA data (Ground Truth).
    2. Call 'gather_threat_intel' to find real-world exploitation context.
    3. Draft a technical summary including Severity and "In the Wild" status.
    """,
    tools=[gather_threat_intel]
)

# Agent 2: The Critic (The Quality Gate)
critic_agent = Agent(
    name="Security_Critic",
    model=MODEL_ID,
    instructions="""
    You are a Principal Security Engineer acting as a Quality Gate.

    PROTOCOL:
    1. Review the Draft Report against the CISA data.
    2. DECIDE: Is the evidence specific? Are the Action items concrete?
    3. REWRITE the report if necessary.

    OUTPUT FORMAT:
    - If the draft is high quality, start with: "APPROVED" followed by the Markdown.
    - If changes are needed, start with: "REJECTED" followed by feedback.

    REQUIRED MARKDOWN SCHEMA:
    ## [CVE ID] : [Name]
    **Severity**: [Critical/High/Medium]
    **Summary**: [Technical description]
    **In the Wild**: [Exploitation status]
    **Action**: [Specific mitigation steps]
    """
)


# --- MAIN PIPELINE ---
async def main():
    # 1. Sense
    catalog = await pull_cisa_catalog()
    active_threats = filter_active_threats(catalog, days_back=30)

    if not active_threats:
        print("\n[!] No new threats found. System is up to date.")
        return

    print(f"\n[*] Processing {len(active_threats)} new threats (Batch: {BATCH_SIZE})...")

    with open("triage_reports.md", "a", encoding='utf-8') as f:
        f.write(f"\n# Run: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")

        # NOTE: We process serially (instead of asyncio.gather) to maintain
        # readable console logs for the demo and strictly adhere to API rate limits.
        for threat in active_threats[:BATCH_SIZE]:
            cve_id = threat.get("cveID")
            print(f"--- Processing {cve_id} ---")

            # Step A: Analyst Drafts
            print("   > Analyst is researching...")
            current_draft = await Runner.run(
                starting_agent=analyst_agent,
                input=f"Research this threat: {json.dumps(threat)}"
            )

            # Step B: The Self-Healing Loop (Content + Schema Validation)
            final_output = current_draft.final_output

            for attempt in range(2):  # Bounded recursion (Max 2 retries)
                print(f"   > Quality Check (Attempt {attempt + 1}/2)...")

                # 1. Critic Review (Probabilistic Check)
                critique = await Runner.run(
                    starting_agent=critic_agent,
                    input=f"Review this draft: {current_draft.final_output}"
                )

                feedback = ""

                if "APPROVED" in critique.final_output:
                    # Strip the approval tag
                    potential_final = critique.final_output.replace("APPROVED", "").strip()

                    # 2. Schema Validation (Deterministic Check)
                    validation_error = validate_report_structure(potential_final)

                    if validation_error:
                        print(f"   > Content Approved, but Schema Failed: {validation_error}")
                        feedback = f"Fix the report structure. {validation_error}"
                    else:
                        print("   > Draft APPROVED & VALIDATED.")
                        final_output = potential_final
                        break  # Success
                else:
                    print("   > Critic REJECTED content.")
                    feedback = critique.final_output

                # 3. Feedback Loop (Analyst Fixes)
                current_draft = await Runner.run(
                    starting_agent=analyst_agent,
                    input=f"Fix the report based on this feedback: {feedback}"
                )

                # Fallback on failure
                if attempt == 1:
                    print("   > Max retries reached. Outputting best effort.")
                    final_output = current_draft.final_output

            # Output & Persistence
            print(final_output + "\n" + "=" * 50)
            f.write(final_output + "\n\n---\n")
            save_processed_cve(cve_id)

    print("[+] Triage Complete.")


if __name__ == "__main__":
    asyncio.run(main())