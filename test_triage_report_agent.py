import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
import asyncio
import os

# Import the logic
from triage_report_agent import filter_active_threats, validate_report_structure, fetch_threat_context

class TestTriageAgent(unittest.TestCase):

    def test_filter_active_threats(self):
        """Test that fresh vulnerabilities and identified and processed ones are skipped."""
        today = datetime.now()
        old_date = (today - timedelta(days=100)).strftime("%Y-%m-%d")
        new_date = (today - timedelta(days=2)).strftime("%Y-%m-%d")

        mock_data = [
            {"cveID": "CVE-OLD", "dateAdded": old_date},
            {"cveID": "CVE-NEW", "dateAdded": new_date},
            {"cveID": "CVE-DONE", "dateAdded": new_date}
        ]

        with patch('triage_report_agent.load_processed_cves', return_value={"CVE-DONE"}):
            result = filter_active_threats(mock_data, days_back=30)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['cveID'], "CVE-NEW")

    def test_validate_report_structure(self):
        """Test the schema validator."""
        good_text = "## Title\n**Severity**: High\n**Summary**: ...\n**In the Wild**: ...\n**Action**: ..."
        self.assertIsNone(validate_report_structure(good_text))

        bad_text = "Just some text"
        self.assertIsNotNone(validate_report_structure(bad_text))

    @patch('triage_report_agent.TavilyClient')
    def test_gather_threat_intel(self, MockTavily):
        """Test the Async Tool Logic."""
        mock_client = MockTavily.return_value
        mock_client.search.return_value = {"results": [{"content": "PoC found on GitHub"}]}

        with patch.dict(os.environ, {'TAVILY_API_KEY': 'fake-key'}):
            # Call the LOGIC function here
            result = asyncio.run(fetch_threat_context("CVE-2025-TEST"))

        self.assertIn("PoC found", result)


if __name__ == '__main__':
    unittest.main()