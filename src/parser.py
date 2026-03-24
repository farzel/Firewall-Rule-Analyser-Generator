from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator, TypedDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / 'data' / 'generated_50k_config.conf'
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / 'output' / 'parsed_rules.json'


class RuleRecord(TypedDict, total=False):
    """Normalised FortiOS firewall rule representation."""

    rule_id: str
    action: str
    srcaddr: str
    dstaddr: str
    service: str
    logtraffic: str


def _clean_value(raw_value: str) -> str:
    value = raw_value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def iter_fortios_policies(config_file_path: str | Path) -> Iterator[RuleRecord]:
    """Yield FortiOS firewall policies one-by-one in file order."""
    current_policy: RuleRecord | None = None
    in_policy_block = False

    with Path(config_file_path).open('r', encoding='utf-8', buffering=1024 * 1024) as file:
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
                if current_policy is not None:
                    yield current_policy
                    current_policy = None
                continue

            if line.startswith('edit '):
                if current_policy is not None:
                    yield current_policy
                current_policy = {'rule_id': line[5:].strip()}
                continue

            if current_policy is None or not line.startswith('set '):
                continue

            payload = line[4:]
            key, separator, value = payload.partition(' ')
            if separator:
                current_policy[key] = _clean_value(value)

    if current_policy is not None:
        yield current_policy


def parse_fortios_policies(config_file_path: str | Path) -> list[dict[str, Any]]:
    """Parse a FortiOS config file and return firewall policies as dictionaries."""
    try:
        return list(iter_fortios_policies(config_file_path))
    except FileNotFoundError:
        print(f'Error: The file {config_file_path} was not found.')
        return []


if __name__ == '__main__':
    print(f'Reading configuration from: {DEFAULT_CONFIG_PATH}')
    parsed_rules = parse_fortios_policies(DEFAULT_CONFIG_PATH)

    if parsed_rules:
        DEFAULT_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with DEFAULT_OUTPUT_PATH.open('w', encoding='utf-8') as out_file:
            json.dump(parsed_rules, out_file, indent=4)
        print(f'Success! Parsed {len(parsed_rules)} rules and saved to:\n{DEFAULT_OUTPUT_PATH}')
    else:
        print('No rules were parsed. Please check the file path and contents.')
