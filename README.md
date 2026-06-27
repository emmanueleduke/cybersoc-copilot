CyberSOC Copilot 
AI Multi-Agent Security Operations System built with Google ADK 2.0 and Antigravity IDE.

What it does
- Triages security alerts by severity (Critical/High/Medium/Low)
- Enriches IP addresses with real threat intelligence from VirusTotal and AbuseIPDB
- Generates structured incident reports with recommended response actions
- Reduces analyst workload and accelerates threat response

Architecture
Multi-agent system built on Google ADK 2.0:
- **Manager Agent** (cybersoc_manager): Orchestrates the investigation workflow
- **triage_alert tool**: Classifies alert severity using pattern matching
- **enrich_ip_virustotal tool**: Queries VirusTotal for malicious detections
- **enrich_ip_abuseipdb tool**: Queries AbuseIPDB for abuse confidence score

Requirements
- Python 3.11+
- uv package manager
- Google Cloud project with Vertex AI enabled
- VirusTotal API key (free tier)
- AbuseIPDB API key (free tier)

Setup
1. Install dependencies:
uvx google-agents-cli setup
uv sync

2. Set environment variables:
cp .env.example .env

Edit .env with your actual keys

3. Authenticate with Google Cloud:
gcloud auth application-default login --scopes=https://www.googleapis.com/auth/cloud-platform
gcloud config set project YOUR_PROJECT_ID
gcloud services enable aiplatform.googleapis.com

4. Run the agent:
uv run adk web --host 127.0.0.1 --port 8080

5. Open http://127.0.0.1:8080 and submit an alert:
Investigate this alert: suspicious outbound connection detected from IP 185.220.101.45 on port 4444

Environment Variables
| Variable | Description |
|---|---|
| GOOGLE_GENAI_USE_VERTEXAI | Set to "True" for Vertex AI |
| GOOGLE_CLOUD_PROJECT | Your GCP project ID |
| GOOGLE_CLOUD_LOCATION | GCP region (e.g. us-central1) |
| VIRUSTOTAL_API_KEY | From virustotal.com |
| ABUSEIPDB_API_KEY | From abuseipdb.com |

Built With
- Google ADK 2.0
- Google Antigravity IDE
- Agents CLI
- Gemini 2.5 Flash (Vertex AI)
- VirusTotal API
- AbuseIPDB API

Kaggle Capstone
Submitted to the Kaggle 5-Day AI Agents Intensive Vibe Coding Capstone 2026 — Agents for Business track.
