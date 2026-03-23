from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT_PATH = PROJECT_ROOT / 'output' / 'parsed_rules.json'
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / 'output' / 'vulnerability_report.json'
ACCEPT_ACTION = 'accept'
ALL_VALUE = 'all'
DISABLE_LOGGING = 'disable'


def _normalise(value: Any, default: str = '') -> str:
    if value is None:
        return default
    return str(value).strip().lower()


def analyze_rules(parsed_rules: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Scan parsed firewall rules for common security vulnerabilities."""
    vulnerabilities: list[dict[str, str]] = []
    catch_all_rule_id: str | None = None

    for rule in parsed_rules:
        rule_id = str(rule.get('rule_id', 'Unknown'))
        action = _normalise(rule.get('action'))
        srcaddr = _normalise(rule.get('srcaddr'))
        dstaddr = _normalise(rule.get('dstaddr'))
        logtraffic = _normalise(rule.get('logtraffic'))

        if action == ACCEPT_ACTION and srcaddr == ALL_VALUE and dstaddr == ALL_VALUE:
            vulnerabilities.append(
                {
                    'rule_id': rule_id,
                    'issue': 'Overly Permissive Rule',
                    'severity': 'High',
                    'description': 'Rule allows ALL source traffic to ALL destinations. This violates the principle of least privilege.',
                }
            )
            catch_all_rule_id = rule_id

        if action == ACCEPT_ACTION and logtraffic == DISABLE_LOGGING:
            vulnerabilities.append(
                {
                    'rule_id': rule_id,
                    'issue': 'Logging Disabled',
                    'severity': 'Medium',
                    'description': 'Rule accepts traffic but logging is disabled. This creates a blind spot for incident response.',
                }
            )

        if catch_all_rule_id and rule_id != catch_all_rule_id:
            vulnerabilities.append(
                {
                    'rule_id': rule_id,
                    'issue': 'Shadowed Rule',
                    'severity': 'Medium',
                    'description': f'This rule is shadowed by overly permissive Rule {catch_all_rule_id} higher up in the policy list and will never trigger.',
                }
            )

    return vulnerabilities


if __name__ == '__main__':
    DEFAULT_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    try:
        with DEFAULT_INPUT_PATH.open('r', encoding='utf-8') as infile:
            rules = json.load(infile)

        print(f'Analyzing {len(rules)} rules...\n')
        report = analyze_rules(rules)

        if report:
            print('⚠️ Vulnerabilities Found:')
            print(json.dumps(report, indent=4))

            with DEFAULT_OUTPUT_PATH.open('w', encoding='utf-8') as outfile:
                json.dump(report, outfile, indent=4)
            print(f'\n✅ Report successfully saved to:\n{DEFAULT_OUTPUT_PATH}')
        else:
            print('✅ No vulnerabilities found! The configuration looks secure.')

    except FileNotFoundError:
        print(f'❌ Error: Could not find {DEFAULT_INPUT_PATH}. Did you run parser.py first?')
