import json
import os

def analyze_rules(parsed_rules):
    """
    Scans a list of parsed firewall rules for common security vulnerabilities.
    Returns a list of identified issues.
    """
    vulnerabilities = []
    seen_catch_all = False
    catch_all_rule_id = None

    for rule in parsed_rules:
        rule_id = rule.get('rule_id', 'Unknown')
        action = rule.get('action', '')
        srcaddr = rule.get('srcaddr', '')
        dstaddr = rule.get('dstaddr', '')
        logtraffic = rule.get('logtraffic', '')

        # Vulnerability 1: Overly Permissive Rule (ANY to ANY)
        if action == "accept" and srcaddr == "all" and dstaddr == "all":
            vulnerabilities.append({
                "rule_id": rule_id,
                "issue": "Overly Permissive Rule",
                "severity": "High",
                "description": "Rule allows ALL source traffic to ALL destinations. This violates the principle of least privilege."
            })
            # Mark that we've seen a catch-all, which means subsequent rules might be shadowed
            seen_catch_all = True
            catch_all_rule_id = rule_id

        # Vulnerability 2: Logging Disabled on Accept Rules
        if action == "accept" and logtraffic == "disable":
            vulnerabilities.append({
                "rule_id": rule_id,
                "issue": "Logging Disabled",
                "severity": "Medium",
                "description": "Rule accepts traffic but logging is disabled. This creates a blind spot for incident response."
            })

        # Vulnerability 3: Shadowed Rules
        # If a previous rule allowed ALL traffic, this current rule will never be triggered.
        elif seen_catch_all and rule_id != catch_all_rule_id:
             vulnerabilities.append({
                "rule_id": rule_id,
                "issue": "Shadowed Rule",
                "severity": "Medium",
                "description": f"This rule is shadowed by overly permissive Rule {catch_all_rule_id} higher up in the policy list and will never trigger."
            })

    return vulnerabilities

if __name__ == "__main__":
    # 1. Set up bulletproof file paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Safely define the output directory
    output_dir = os.path.join(script_dir, "..", "output")
    os.makedirs(output_dir, exist_ok=True)
    
    input_path = os.path.join(output_dir, "parsed_rules.json")
    output_path = os.path.join(output_dir, "vulnerability_report.json")

    # 2. Load the parsed data
    try:
        with open(input_path, 'r') as infile:
            rules = json.load(infile)
            
        print(f"Analyzing {len(rules)} rules...\n")
        
        # 3. Run the analysis
        report = analyze_rules(rules)

        # 4. Output the results
        if report:
            print("⚠️ Vulnerabilities Found:")
            print(json.dumps(report, indent=4))
            
            # Save the executive report
            with open(output_path, 'w') as outfile:
                json.dump(report, outfile, indent=4)
            print(f"\n✅ Report successfully saved to:\n{output_path}")
        else:
            print("✅ No vulnerabilities found! The configuration looks secure.")

    except FileNotFoundError:
        print(f"❌ Error: Could not find {input_path}. Did you run parser.py first?")