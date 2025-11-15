import requests

OTX_API = "YOUR_OTX_API_KEY"

def otx_check(ioc):
    # try to detect IOC type
    if ioc.count(".") == 3 and all(x.isdigit() for x in ioc.split(".")):
        indicator_type = "IPv4"
    elif "." in ioc:
        indicator_type = "domain"
    elif len(ioc) > 20:
        indicator_type = "file"       # Hash
    else:
        indicator_type = "url"

    url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{ioc}/general"
    headers = {"X-OTX-API-KEY": OTX_API.strip()}

    try:
        r = requests.get(url, headers=headers)

        if r.status_code == 403:
            return "OTX → Invalid API Key OR not allowed for this IOC type"
        if r.status_code == 404:
            return "OTX → IOC not found"
        if r.status_code != 200:
            return "OTX → Error (Rate limit or bad IOC type)"

        data = r.json()
        pulse_count = len(data.get("pulse_info", {}).get("pulses", []))
        return f"OTX → Listed in {pulse_count} threat pulses"

    except:
        return "OTX → Error while connecting"
