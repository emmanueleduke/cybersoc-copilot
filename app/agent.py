import os
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "True"

import requests
from google.adk.agents import Agent
from google.adk.apps import App
from google.adk.models import Gemini
from google.genai import types
from dotenv import load_dotenv
load_dotenv()




def triage_alert(alert_description: str) -> str:
    """Classifies a security alert by severity.
    Args:
        alert_description: Raw alert text from SIEM or analyst.
    Returns:
        Severity classification with reasoning.
    """
    keywords = {
        "Critical": ["ransomware", "data exfiltration", "privilege escalation", "lateral movement"],
        "High": ["malware", "brute force", "port scan", "suspicious outbound"],
        "Medium": ["failed login", "unusual traffic", "policy violation"],
        "Low": ["info", "reconnaissance", "low confidence"],
    }
    alert_lower = alert_description.lower()
    for severity, terms in keywords.items():
        if any(term in alert_lower for term in terms):
            return f"Severity: {severity}\nAlert: {alert_description}\nReason: Matched pattern for {severity} indicators."
    return f"Severity: Low\nAlert: {alert_description}\nReason: No high-risk patterns detected."
def enrich_ip_virustotal(ip_address: str) -> str:
    """Enriches an IP address using VirusTotal threat intelligence.
    Args:
        ip_address: The IP address to investigate.
    Returns:
        Threat intelligence report for the IP.
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return "VirusTotal API key not configured."
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            country = data.get("data", {}).get("attributes", {}).get("country", "Unknown")
            return f"IP: {ip_address}\nCountry: {country}\nMalicious detections: {malicious}\nSuspicious detections: {suspicious}"
        return f"VirusTotal returned status {response.status_code} for IP {ip_address}"
    except Exception as e:
        return f"VirusTotal lookup failed: {str(e)}"
def enrich_ip_abuseipdb(ip_address: str) -> str:
    """Checks an IP address against AbuseIPDB.
    Args:
        ip_address: The IP address to check.
    Returns:
        Abuse confidence score and report count.
    """
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return "AbuseIPDB API key not configured."
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            reports = data.get("totalReports", 0)
            domain = data.get("domain", "Unknown")
            return f"IP: {ip_address}\nAbuse Confidence Score: {score}%\nTotal Reports: {reports}\nDomain: {domain}"
        return f"AbuseIPDB returned status {response.status_code} for IP {ip_address}"
    except Exception as e:
        return f"AbuseIPDB lookup failed: {str(e)}"

root_agent = Agent(
    name="cybersoc_manager",
    model=Gemini(
        model="gemini-2.5-flash",
        retry_options=types.HttpRetryOptions(attempts=3),
    ),
    instruction="""You are CyberSOC Copilot, a multi-agent security operations assistant.

When given a security alert:
1. Call triage_alert to classify the severity
2. Extract any IP addresses from the alert
3. Call enrich_ip_virustotal and enrich_ip_abuseipdb for each IP
4. Synthesize a final incident report with:
   - Severity classification
   - Threat intelligence summary
   - Recommended response actions

Be precise, structured, and prioritize analyst efficiency.""",
    tools=[triage_alert, enrich_ip_virustotal, enrich_ip_abuseipdb],
)

app = App(
    root_agent=root_agent,
    name="app",
)