import requests

TOR_EXIT_NODE_FEED = "https://check.torproject.org/torbulkexitlist"
BOTNET_FEED = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/botnet.ipset"

def fetch_feed(url):
    try:
        data = requests.get(url, timeout=8).text.splitlines()
        return [x.strip() for x in data if x.strip() and not x.startswith("#")]
    except Exception:
        return []
