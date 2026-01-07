import asyncio
import requests
import json
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

from agents import Agent, Runner, function_tool
from tavily import TavilyClient

load_dotenv()

# Constants
CISA_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MODEL_ID = "gpt-5-mini"

def pull_cisa_catalog():
    """
    Downloads the Official KEV catalog from CISA
    Returns a list of vulnerability dictionaries
    """
    print("Connecting to CISA feed")
    try:
        response = requests.get(CISA_JSON_URL)
        response.raise_for_status()

        cisa_feed = response.json()
        kev_list = cisa_feed.get("vulnerabilities", [])

        print(f"Downloaded {len(kev_list)} vulnerabilities.")
        return kev_list

    except Exception as error:
        print(f"Network Error: {error}")
        return []

def filter_active_threats(kev_list, days_back=30):

    cutoff_date = datetime.now() - timedelta(days=days_back)
    active_threats = []

    for threat in kev_list:
        date_str = threat.get("dateAdded")

        try:
                # CISA dates are YYYY-MM-DD
                added_date = datetime.strptime(date_str, "%Y-%m-%d")

                if added_date > cutoff_date:
                    active_threats.append(threat)
        except ValueError:
            continue

    return sorted(active_threats, key=lambda x: x["dateAdded"], reverse=True)

@function_tool
def gather_threat_intel(cve_id: str) -> str:
    """
    Tool: Searches the web for technical details about a CVE.
    """
    print(f" TOOL: Searching context for {cve_id}...")


    api_key = os.getenv("TAVILY_API_KEY")
    if not api_key:
        return "Error: TAVILY_API_KEY not found in .env"



    try:
        tavily = TavilyClient()
        response = tavily.search(
            query=f"{cve_id} exploit analysis technical details",
            search_depth="basic",
            max_results=3
        )

        # Tavily returns a clean list of dictionaries
        context = response.get("results", [])

        if not context:
            return "No external context found."

        return json.dumps(context)

    except Exception as e:
        return f"Search Error: {e}"


triage_agent = Agent(
    name="CISA_Triage_Bot",
    model=MODEL_ID,
    instructions="""
    You are a Senior Vulnerability Analyst.
    Your goal is to triage a CVE by combining official data with web search results.

    PROTOCOL:
    1. Analyze the input CVE data.
    2. Call 'gather_threat_intel' to find real-world exploit context.
    3. Output a Final Report in Markdown.

    REPORT FORMAT:
    ## [CVE ID] : [Name]
    **Severity**: [Critical/High/Medium]
    **Summary**: [Brief technical description]
    **In the Wild**: [Exploitation status based on search]
    **Action**: [Immediate mitigation steps]
    """,
    tools=[gather_threat_intel]
)

#Quick accuracy check

async def main():
    # 1. Sense
    catalog = pull_cisa_catalog()
    active_threats = filter_active_threats(catalog, days_back=30)

    print(f"\n[*] Triage Queue: {len(active_threats)} vulnerabilities found.\n")

    # 2. Generate report
    with open("triage_reports.md", "w", encoding='utf-8') as f:
        f.write("# Daily Triage Report\n\n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d')}\n")
        f.write(f"**Threats Found:** {len(active_threats)}\n\n")

        for threat in active_threats[:2]:
            cve_id = threat.get("cveID")
            print(f"--- Processing {cve_id} ---")

            # Run the Agent
            result = await Runner.run(
                starting_agent=triage_agent,
                input=f"Triage this threat: {json.dumps(threat)}"
            )

            # Print to console
            print(result.final_output)
            print("\n" + "=" * 50 + "\n")

            # Output to file
            f.write(result.final_output + "\n")
            f.write("\n---\n")
    print(f"Report generated: triage_reports.md")

# 3. Execution Entry Point
if __name__ == "__main__":
    # We use asyncio.run() to execute the async main function
    asyncio.run(main())

