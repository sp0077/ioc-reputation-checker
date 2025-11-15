import requests

ABUSE_API = "YOUR_ABUSEIPDB_API_KEY"

def abuse_check(ip):
    # Validate: AbuseIPDB only works for IP addresses
    try:
        octets = ip.split(".")
        if len(octets) != 4 or not all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
            return "AbuseIPDB → Only works for IP addresses"
    except:
        return "AbuseIPDB → Invalid IP format"

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {
        "Key": ABUSE_API.strip(),
        "Accept": "application/json"
    }

    try:
        r = requests.get(url, params=params, headers=headers)

        if r.status_code == 403:
            return "AbuseIPDB → Invalid API Key"
        if r.status_code == 429:
            return "AbuseIPDB → Rate limit reached"
        if r.status_code != 200:
            return f"AbuseIPDB → Error ({r.status_code})"

        data = r.json()
        score = data["data"]["abuseConfidenceScore"]
        return f"AbuseIPDB → Confidence Score: {score}"

    except:
        return "AbuseIPDB → Error connecting to API"
