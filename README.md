# Automated FortiOS Firewall Rule Analyser

## Overview
This repository contains an automated vulnerability detection engine for Fortinet (FortiOS) firewall configurations. It is engineered to parse complex rule sets, normalise the data into structured JSON, and systematically hunt for logical flaws and security misconfigurations. 

This tool was developed as part of an MSc cybersecurity project to demonstrate the practical application of automated analysis and AI-assisted development in modern network security workflows. It features a fully interactive web dashboard for real-time threat intelligence.

## Core Features
* **Interactive Threat Dashboard:** A local web application built with Streamlit, allowing assessors to drag-and-drop configuration files for instant visual analysis.
* **Configuration Parsing:** Automatically extracts and structures raw FortiOS `set` and `edit` commands into machine-readable JSON arrays.
* **Vulnerability Detection Engine:** Scans parsed rule sets to identify:
    * **Overly Permissive Rules:** Flags rules allowing `all` traffic from `all` sources (violating the principle of least privilege).
    * **Logging Blind Spots:** Detects `accept` rules where `logtraffic` has been dangerously disabled.
    * **Shadowed Rules:** Identifies the "Cascade Effect" where overly broad rules higher in the chain render subsequent rules useless.
* **Enterprise-Scale Chaos Testing:** Includes a bespoke data generator capable of synthesising 50,000+ realistic firewall rules using true probability mathematics to ensure unique, unpredictable datasets on every run.

## Project Structure
```text
Firewall-Rule-Analyser-Generator/
│
├── src/
│   ├── generator.py    # Synthesises 50k+ randomised test rules
│   ├── parser.py       # Converts .conf files to JSON
│   ├── analyser.py     # Hunts for vulnerabilities
│   └── dashboard.py    # Interactive Streamlit Web UI
│
├── data/
│   └── generated_50k_config.conf  # Raw input data
│
├── output/
│   ├── parsed_rules.json          # Structured data
│   └── vulnerability_report.json  # Final security report
│
└── README.md