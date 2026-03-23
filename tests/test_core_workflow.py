from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = PROJECT_ROOT / 'src'
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from analyser import analyze_rules
from parser import parse_fortios_policies

SAMPLE_CONFIG_PATH = PROJECT_ROOT / 'data' / 'sample_fortigate_config.conf'


class CoreWorkflowTests(unittest.TestCase):
    def test_parser_extracts_expected_rules_from_sample_config(self) -> None:
        parsed_rules = parse_fortios_policies(SAMPLE_CONFIG_PATH)

        self.assertEqual(len(parsed_rules), 3)
        self.assertEqual(parsed_rules[0]['rule_id'], '1')
        self.assertEqual(parsed_rules[0]['name'], 'Allow-Internal-Outbound')
        self.assertEqual(parsed_rules[1]['srcaddr'], 'all')
        self.assertEqual(parsed_rules[2]['action'], 'deny')

    def test_analyser_flags_expected_issues_for_sample_rules(self) -> None:
        parsed_rules = parse_fortios_policies(SAMPLE_CONFIG_PATH)
        report = analyze_rules(parsed_rules)

        self.assertEqual(
            report,
            [
                {
                    'rule_id': '2',
                    'issue': 'Overly Permissive Rule',
                    'severity': 'High',
                    'description': 'Rule allows ALL source traffic to ALL destinations. This violates the principle of least privilege.',
                },
                {
                    'rule_id': '2',
                    'issue': 'Logging Disabled',
                    'severity': 'Medium',
                    'description': 'Rule accepts traffic but logging is disabled. This creates a blind spot for incident response.',
                },
                {
                    'rule_id': '3',
                    'issue': 'Shadowed Rule',
                    'severity': 'Medium',
                    'description': 'This rule is shadowed by overly permissive Rule 2 higher up in the policy list and will never trigger.',
                },
            ],
        )


if __name__ == '__main__':
    unittest.main()
