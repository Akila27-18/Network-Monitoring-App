from .models import ThreatIP
from .feed_sources import fetch_feed, TOR_EXIT_NODE_FEED, BOTNET_FEED

def update_threat_feeds():

    feeds = {
        "Tor Exit Node": fetch_feed(TOR_EXIT_NODE_FEED),
        "Botnet Activity": fetch_feed(BOTNET_FEED),
    }

    added = 0

    for source, ip_list in feeds.items():
        for ip in ip_list:
            if not ThreatIP.objects.filter(ip=ip).exists():
                ThreatIP.objects.create(ip=ip, source=source)
                added += 1

    return added
