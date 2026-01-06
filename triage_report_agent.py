import requests
import json
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

# Constants
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


#Quick accuracy check

if __name__ == "__main__":
    catalog = pull_cisa_catalog()

    #Check if fetch worked
    if catalog:
        recent = filter_active_threats(catalog, days_back=30)
        print(f"Found {len(recent)} active threats in the last 30 days")


    #print first one to confirm structure
    if recent:
        print(f"Sample: {recent[0]['cveID']} - {recent[0]['vulnerabilityName']}")

