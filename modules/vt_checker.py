import requests
import time
import base64

# Put your VirusTotal API key here
VT_API = "YOUR_VIRUSTOTAL_API_KEY"


# ----------------------------------------------------------
# AUTO-DETECT IOC TYPE (URL / IP / DOMAIN / HASH)
# ----------------------------------------------------------
def detect_ioc_type(ioc):
    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"
    elif "/" in ioc and "." in ioc:
        return "url"    # URL without https
    elif ioc.count(".") == 3 and all(x.isdigit() for x in ioc.split(".")):
        return "ip"
    elif "." in ioc:
        return "domain"
    elif len(ioc) >= 32:
        return "hash"
    else:
        return "unknown"


# ----------------------------------------------------------
# VIRUSTOTAL REQUIRES URL ENCODING FOR certain lookups
# ----------------------------------------------------------
def vt_encode_url(url):
    encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return encoded


# ----------------------------------------------------------
# 1. SUBMIT URL FOR SCANNING (POST REQUEST)
# ----------------------------------------------------------
def vt_submit_url(url):
    endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VT_API}
    data = {"url": url}

    try:
        r = requests.post(endpoint, headers=headers, data=data)
        if r.status_code != 200:
            return None, f"VT → Error submitting URL ({r.status_code})"

        scan_id = r.json()["data"]["id"]
        return scan_id, None

    except:
        return None, "VT → Submission failed"


# ----------------------------------------------------------
# 2. GET URL ANALYSIS REPORT
# ----------------------------------------------------------
def vt_get_url_report(scan_id):
    endpoint = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    headers = {"x-apikey": VT_API}

    try:
        for _ in range(8):  # Up to 8 seconds wait
            r = requests.get(endpoint, headers=headers)

            if r.status_code != 200:
                return f"VT → Unable to fetch report ({r.status_code})"

            data = r.json()
            status = data["data"]["attributes"]["status"]

            if status == "completed":
                stats = data["data"]["attributes"]["stats"]
                malicious = stats["malicious"]
                suspicious = stats["suspicious"]
                return f"VT → Malicious: {malicious}, Suspicious: {suspicious}"

            time.sleep(1)

        return "VT → Scan timeout"

    except:
        return "VT → Analysis error"


# ----------------------------------------------------------
# 3. LOOKUP FOR IP / DOMAIN / HASH
# ----------------------------------------------------------
def vt_lookup(ioc):
    endpoint = f"https://www.virustotal.com/api/v3/search?query={ioc}"
    headers = {"x-apikey": VT_API}

    try:
        r = requests.get(endpoint, headers=headers)

        if r.status_code != 200:
            return f"VT → Lookup error ({r.status_code})"

        data = r.json()

        if "data" not in data or len(data["data"]) == 0:
            return "VT → No data found"

        stats = data["data"][0]["attributes"]["last_analysis_stats"]
        malicious = stats["malicious"]
        suspicious = stats["suspicious"]

        return f"VT → Malicious: {malicious}, Suspicious: {suspicious}"

    except:
        return "VT → Lookup failure"


# ----------------------------------------------------------
# MAIN FUNCTION (CALLED BY main.py)
# ----------------------------------------------------------
def vt_check(ioc):

    # AUTO-ADD https:// IF USER DID NOT WRITE IT
    if "." in ioc and not ioc.startswith(("http://", "https://")):
        ioc = "https://" + ioc

    ioc_type = detect_ioc_type(ioc)

    # URL SCANNING
    if ioc_type == "url":
        scan_id, error = vt_submit_url(ioc)
        if error:
            return error
        return vt_get_url_report(scan_id)

    # IP / DOMAIN / HASH LOOKUP
    return vt_lookup(ioc)
