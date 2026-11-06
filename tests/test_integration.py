
import csv
import json
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

from src import analyzer


class IntegrationTests(unittest.TestCase):

    def test_complete_analysis_pipeline(self):

        fixture = Path("tests/fixtures/brute_force.log")

        with tempfile.TemporaryDirectory() as temp_dir:

            output_dir = Path(temp_dir)

            csv_file = output_dir / "analysis.csv"
            json_file = output_dir / "alerts.json"

            with patch.object(analyzer, "INPUT_FILE", fixture), \
                 patch.object(analyzer, "OUTPUT_CSV", csv_file), \
                 patch.object(analyzer, "OUTPUT_JSON", json_file):

                analyzer.analyze()

            # Validate CSV report
            with csv_file.open(
                "r", encoding="utf-8"
            ) as file:
                rows = list(csv.DictReader(file))

            self.assertEqual(len(rows), 5)
            self.assertEqual(rows[0]["source_ip"], "IP_001")
            self.assertEqual(rows[0]["username"], "USER_001")

            # Validate JSON alerts
            with json_file.open(
                "r", encoding="utf-8"
            ) as file:
                alerts = json.load(file)

            self.assertEqual(len(alerts), 1)
            self.assertEqual(
                alerts[0]["rule_id"],
                "SSH_BRUTE_FORCE"
            )
            self.assertEqual(alerts[0]["severity"], "HIGH")
            self.assertEqual(alerts[0]["event_count"], 5)
            self.assertEqual(alerts[0]["source_ip"], "IP_001")


if __name__ == "__main__":
    unittest.main()
