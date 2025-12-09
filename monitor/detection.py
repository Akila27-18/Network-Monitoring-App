from monitor.models import NetworkLog, Alert
from datetime import datetime, timedelta
from django.db.models import Count, Sum



def detect_high_traffic():
    window = datetime.now() - timedelta(minutes=5)

    heavy = (
        NetworkLog.objects
        .filter(timestamp__gte=window)
        .values("source_ip")
        .annotate(total=Sum("bytes_transferred"))
        .filter(total__gte=1000000)  # 1 MB threshold
    )

    for item in heavy:
        Alert.objects.create(
            message=f"High bandwidth usage from {item['source_ip']} ({item['total']} bytes)",
            severity="High"
        )


def detect_port_scan():
    window = datetime.now() - timedelta(minutes=2)

    scans = (
        NetworkLog.objects
        .filter(timestamp__gte=window)
        .values("source_ip")
        .annotate(targets=Count("destination_ip", distinct=True))
        .filter(targets__gte=10)
    )

    for item in scans:
        Alert.objects.create(
            message=f"Possible port scanning detected from {item['source_ip']}",
            severity="Medium"
        )


def detect_icmp_flood():
    window = datetime.now() - timedelta(minutes=1)

    floods = (
        NetworkLog.objects
        .filter(timestamp__gte=window, protocol="ICMP")
        .values("source_ip")
        .annotate(count=Count("id"))
        .filter(count__gte=50)
    )

    for item in floods:
        Alert.objects.create(
            message=f"ICMP flood detected from {item['source_ip']}",
            severity="High"
        )
