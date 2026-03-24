from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Iterator

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT_PATH = PROJECT_ROOT / 'output' / 'parsed_rules.json'
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / 'output' / 'vulnerability_report.json'

ACCEPT_ACTION = 'accept'
ALL_VALUE = 'all'
ANY_VALUE = 'any'
DISABLE_LOGGING = 'disable'
PERMISSIVE_VALUES = frozenset((ALL_VALUE, ANY_VALUE))


def _normalise(value: Any, default: str = '') -> str:
    """Helper function to clean up string comparisons."""
    if value is None:
        return default
    return str(value).strip().lower()


def iter_rule_findings(parsed_rules: Iterable[dict[str, Any]]) -> Iterator[dict[str, str]]:
    """Yield vulnerability findings in a single pass over parsed firewall rules."""
    catch_all_rule_id: str | None = None
    normalise = _normalise
    permissive_values = PERMISSIVE_VALUES

    for rule in parsed_rules:
        rule_id = str(rule.get('rule_id', 'Unknown'))
        action = normalise(rule.get('action'))
        srcaddr = normalise(rule.get('srcaddr'))
        dstaddr = normalise(rule.get('dstaddr'))
        service = normalise(rule.get('service'))
        logtraffic = normalise(rule.get('logtraffic'))

        is_overly_permissive = (
            action == ACCEPT_ACTION
            and srcaddr in permissive_values
            and dstaddr in permissive_values
            and service in permissive_values
        )

        if is_overly_permissive:
            yield {
                'rule_id': rule_id,
                'issue': 'Overly Permissive Rule',
                'severity': 'High',
                'description': 'Rule allows ALL source traffic to ALL destinations/services. This violates the principle of least privilege.',
            }
            if catch_all_rule_id is None:
                catch_all_rule_id = rule_id

        if action == ACCEPT_ACTION and logtraffic == DISABLE_LOGGING:
            yield {
                'rule_id': rule_id,
                'issue': 'Logging Disabled',
                'severity': 'Medium',
                'description': 'Rule accepts traffic but logging is disabled. This creates a blind spot for incident response.',
            }

        if catch_all_rule_id is not None and rule_id != catch_all_rule_id:
            yield {
                'rule_id': rule_id,
                'issue': 'Shadowed Rule',
                'severity': 'Medium',
                'description': f'This rule is shadowed by overly permissive Rule {catch_all_rule_id} higher up in the policy list and will never trigger.',
            }


def analyse_rules(parsed_rules: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Scan parsed firewall rules for common security vulnerabilities."""
    return list(iter_rule_findings(parsed_rules))


if __name__ == '__main__':
    DEFAULT_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    try:
        with DEFAULT_INPUT_PATH.open('r', encoding='utf-8') as infile:
            rules = json.load(infile)

        print(f'Analysing {len(rules)} rules...\n')
        report = analyse_rules(rules)

        if report:
            print(f'⚠️ Found {len(report)} Vulnerabilities!')
            with DEFAULT_OUTPUT_PATH.open('w', encoding='utf-8') as outfile:
                json.dump(report, outfile, indent=4)
            print(f'✅ Full report successfully saved to:\n{DEFAULT_OUTPUT_PATH}')
        else:
            print('✅ No vulnerabilities found! The configuration looks secure.')

    except FileNotFoundError:
        print(f'❌ Error: Could not find {DEFAULT_INPUT_PATH}. Did you run parser.py first?')
