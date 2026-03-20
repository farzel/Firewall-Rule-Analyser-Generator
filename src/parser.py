import re
import json
import os

def parse_fortios_policies(config_file_path):
    """
    Parses a FortiOS configuration file and extracts firewall policies.
    Returns a list of dictionaries containing rule attributes.
    """
    policies = []
    current_policy = {}
    in_policy_block = False

    try:
        with open(config_file_path, 'r') as file:
            for line in file:
                line = line.strip()

                # Detect the start of the firewall policy block
                if line == "config firewall policy":
                    in_policy_block = True
                    continue
                
                # Detect the end of the firewall policy block
                if line == "end" and in_policy_block:
                    break

                if in_policy_block:
                    # Detect a new rule being edited
                    edit_match = re.match(r'^edit\s+(\d+)', line)
                    if edit_match:
                        # Save the previous policy before starting a new one
                        if current_policy:
                            policies.append(current_policy)
                        current_policy = {'rule_id': edit_match.group(1)}
                        continue

                    # Extract the 'set' attributes
                    set_match = re.match(r'^set\s+([a-zA-Z0-9_-]+)\s+(.+)', line)
                    if set_match and current_policy is not None:
                        key = set_match.group(1)
                        value = set_match.group(2).replace('"', '').strip()
                        current_policy[key] = value

            # Append the very last policy in the block
            if current_policy:
                policies.append(current_policy)

        return policies

    except FileNotFoundError:
        print(f"Error: The file {config_file_path} was not found.")
        return []

if __name__ == "__main__":
    # 1. Get the absolute path of the directory where this script lives
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 2. Build the absolute path to the input config file safely
    file_path = os.path.join(script_dir, "..", "data", "sample_fortigate_config.conf")
    
    # 3. Run the parser
    parsed_rules = parse_fortios_policies(file_path)
    
    # 4. Save the output to a file
    if parsed_rules:
        # Safely create the output directory just in case it's missing
        output_dir = os.path.join(script_dir, "..", "output")
        os.makedirs(output_dir, exist_ok=True)
        
        output_path = os.path.join(output_dir, "parsed_rules.json")
        with open(output_path, 'w') as out_file:
            json.dump(parsed_rules, out_file, indent=4)
        print(f"Success! Parsed {len(parsed_rules)} rules and saved to:\n{output_path}")
    else:
        print("No rules were parsed. Please check the file path and contents.")