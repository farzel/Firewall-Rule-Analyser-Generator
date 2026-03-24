import streamlit as st
import json
import pandas as pd
from pathlib import Path
import sys

# --- Bulletproof Pathing & Imports ---
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# We need to tell Python where to find your custom scripts
sys.path.append(str(PROJECT_ROOT / 'src'))

# Import your actual logic engine!
from parser import parse_fortios_policies
from analyser import analyse_rules

# Paths for saving outputs
UPLOAD_DIR = PROJECT_ROOT / 'data'
OUTPUT_DIR = PROJECT_ROOT / 'output'
REPORT_PATH = OUTPUT_DIR / 'vulnerability_report.json'
RULES_PATH = OUTPUT_DIR / 'parsed_rules.json'

# --- Configuration ---
st.set_page_config(page_title="FortiOS Vulnerability Analyser", page_icon="🛡️", layout="wide")

# --- Header Section ---
st.title("🛡️ Automated FortiOS Firewall Analyser")
st.markdown("**MSc Cybersecurity Project — Kingston University**")
st.markdown("Drag and drop a FortiOS `.conf` file below to automatically parse the rules and generate a vulnerability assessment.")
st.markdown("---")

# --- Drag and Drop File Uploader ---
uploaded_file = st.file_uploader("Upload Fortigate Configuration File", type=['conf', 'txt'])

# --- Processing Logic ---
if uploaded_file is not None:
    # 1. Save the dropped file safely to the data folder
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    temp_config_path = UPLOAD_DIR / 'uploaded_config.conf'
    
    with open(temp_config_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
        
    st.success(f"File '{uploaded_file.name}' successfully uploaded.")

    # 2. Run the Engine with visual loading spinners
    with st.spinner("⚙️ Parsing firewall rules into structured data..."):
        parsed_rules = parse_fortios_policies(temp_config_path)
        
    with st.spinner("🕵️‍♂️ Hunting for overly permissive and shadowed rules..."):
        vulnerabilities = analyse_rules(parsed_rules)

    # 3. Save the results to JSON so your output folder stays updated
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(RULES_PATH, 'w', encoding='utf-8') as f:
        json.dump(parsed_rules, f, indent=4)
    with open(REPORT_PATH, 'w', encoding='utf-8') as f:
        json.dump(vulnerabilities, f, indent=4)

    st.markdown("---")

    # --- Top Row: KPI Metrics ---
    st.subheader("Executive Summary")
    col1, col2, col3, col4 = st.columns(4)
    
    total_rules = len(parsed_rules)
    total_vulns = len(vulnerabilities)
    high_sev = sum(1 for v in vulnerabilities if v.get('severity') == 'High')
    med_sev = sum(1 for v in vulnerabilities if v.get('severity') == 'Medium')
    
    col1.metric("Total Rules Analysed", f"{total_rules:,}")
    col2.metric("Total Vulnerabilities", total_vulns)
    col3.metric("🔴 High Severity", high_sev)
    col4.metric("🟠 Medium Severity", med_sev)
    
    st.markdown("---")

    # --- Middle Row: Charts and Visuals ---
    if total_vulns > 0:
        col_chart, col_data = st.columns([1, 2])
        
        with col_chart:
            st.subheader("Issue Distribution")
            df_vulns = pd.DataFrame(vulnerabilities)
            issue_counts = df_vulns['issue'].value_counts()
            st.bar_chart(issue_counts, color="#ff4b4b")
            
        with col_data:
            st.subheader("Actionable Intelligence")
            st.markdown("The following rules require immediate remediation to align with the principle of least privilege.")
            st.dataframe(
                df_vulns[['rule_id', 'severity', 'issue', 'description']], 
                use_container_width=True,
                hide_index=True
            )
            
    else:
        if total_rules > 0:
            st.success("✅ The configuration is secure. No vulnerabilities detected.")
        else:
            st.error("❌ No rules could be parsed. Please check the file format.")

    st.markdown("---")
    st.caption("Developed for academic evaluation. Do not deploy raw configurations directly to production without manual review.")
else:
    st.info(" Please upload a `.conf` file to begin the analysis.")