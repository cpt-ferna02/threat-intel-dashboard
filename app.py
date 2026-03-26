import os
import requests
from flask import Flask, render_template, request
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = Flask(__name__)

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Store query history in memory
history = []

# ── VirusTotal IP Lookup ────────────────────────────────────────────────────
def check_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        data = r.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "country": data.get("country", "N/A"),
            "owner": data.get("as_owner", "N/A"),
        }
    return None

# ── AbuseIPDB Lookup ────────────────────────────────────────────────────────
def check_ip_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    r = requests.get(url, headers=headers, params=params)
    if r.status_code == 200:
        data = r.json()["data"]
        return {
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "domain": data.get("domain", "N/A"),
            "isp": data.get("isp", "N/A"),
        }
    return None

# ── VirusTotal Hash Lookup ──────────────────────────────────────────────────
def check_hash_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        data = r.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "name": data.get("meaningful_name", "N/A"),
            "type": data.get("type_description", "N/A"),
        }
    return None

# ── Routes ──────────────────────────────────────────────────────────────────
@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    query = None
    query_type = None
    error = None

    if request.method == "POST":
        query = request.form.get("query", "").strip()
        query_type = request.form.get("query_type")

        if query:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if query_type == "ip":
                vt = check_ip_virustotal(query)
                abuse = check_ip_abuseipdb(query)
                if vt or abuse:
                    results = {"vt": vt, "abuse": abuse, "type": "ip"}
                    history.append({
                        "timestamp": timestamp,
                        "query": query,
                        "type": "IP",
                        "malicious": vt["malicious"] if vt else "N/A",
                        "abuse_score": abuse["abuse_score"] if abuse else "N/A"
                    })
                else:
                    error = "Could not retrieve data. Check your API keys or IP address."

            elif query_type == "hash":
                vt = check_hash_virustotal(query)
                if vt:
                    results = {"vt": vt, "type": "hash"}
                    history.append({
                        "timestamp": timestamp,
                        "query": query[:20] + "...",
                        "type": "Hash",
                        "malicious": vt["malicious"],
                        "abuse_score": "N/A"
                    })
                else:
                    error = "Hash not found or invalid. Try a known MD5/SHA256 hash."

    return render_template("index.html", results=results, query=query,
                           query_type=query_type, history=history, error=error)

if __name__ == "__main__":
    app.run(debug=True)