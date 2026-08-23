# cyber-map

AI-Powered Attack Surface Management & Threat Intelligence Engine using Neo4j and OSINT.

## Architecture & Features
* *Multi-Source Recon:* Passive subdomain discovery via DNS brute-force and crt.sh Certificate Transparency logs.
* *Host & Vulnerability Intel:* Shodan API integration for port exposure, running services, and CVE tracking.
* *Graph Modeling:* Neo4j graph database topology connecting Domains, Subdomains, IPs, Ports, Services, and CVEs.
* *AI Attack Path Analysis:* LLM-powered reasoning to detect high-risk attack vectors, MITRE ATT&CK techniques, and blue team remediation steps.

## Tech Stack
* Python 3.10+
* Neo4j & Cypher Query Language
* Docker & Docker Compose
* OpenAI API & Shodan API

## Quick Start
1. Start the Neo4j database:
   ```bash
   docker-compose up -d
