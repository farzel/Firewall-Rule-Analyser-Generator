from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

EDIT_PATTERN = re.compile(r'^edit\s+(\d+)')
SET_PATTERN = re.compile(r'^set\s+([a-zA-Z0-9_-]+)\s+(.+)')
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / 'data' / 'sample_fortigate_config.conf'
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / 'output' / 'parsed_rules.json'


def _clean_value(raw_value: str) -> str:
    return raw_value.replace('"', '').strip()


def parse_fortios_policies(config_file_path: str | Path) -> list[dict[str, Any]]:
    """Parse a FortiOS configuration file and return firewall policies as dictionaries."""
    policies: list[dict[str, Any]] = []
    current_policy: dict[str, Any] | None = None
    in_policy_block = False

    try:
        with Path(config_file_path).open('r', encoding='utf-8') as file:
            for raw_line in file:
                line = raw_line.strip()
                if not line:
                    continue

                if not in_policy_block:
                    if line == 'config firewall policy':
                        in_policy_block = True
                    continue

                if line == 'end':
                    break

                if line == 'next':
                    if current_policy:
                        policies.append(current_policy)
                        current_policy = None
                    continue

                edit_match = EDIT_PATTERN.match(line)
                if edit_match:
                    if current_policy:
                        policies.append(current_policy)
                    current_policy = {'rule_id': edit_match.group(1)}
                    continue

                if current_policy is None:
                    continue

                set_match = SET_PATTERN.match(line)
                if set_match:
                    key, value = set_match.groups()
                    current_policy[key] = _clean_value(value)

        if current_policy:
            policies.append(current_policy)

        return policies

    except FileNotFoundError:
        print(f'Error: The file {config_file_path} was not found.')
        return []


if __name__ == '__main__':
    parsed_rules = parse_fortios_policies(DEFAULT_CONFIG_PATH)

    if parsed_rules:
        DEFAULT_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with DEFAULT_OUTPUT_PATH.open('w', encoding='utf-8') as out_file:
            json.dump(parsed_rules, out_file, indent=4)
        print(f'Success! Parsed {len(parsed_rules)} rules and saved to:\n{DEFAULT_OUTPUT_PATH}')
    else:
        print('No rules were parsed. Please check the file path and contents.')
