import os
import django
import time
from django.utils import timezone

# -------------------------------------------------------------------
# 1. Django must load BEFORE importing models
# -------------------------------------------------------------------
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "network_monitor.settings")
django.setup()

from scapy.all import sniff, IP, conf, get_if_list
from monitor.models import NetworkLog, Alert

# ThreatIntel app optional
try:
    from threatintel.models import ThreatIP
    THREAT_INTEL_ENABLED = True
except Exception:
    THREAT_INTEL_ENABLED = False

from monitor.detection import detect_high_traffic, detect_port_scan, detect_icmp_flood


# -------------------------------------------------------------------
# 2. Detect the correct network interface for Windows
# -------------------------------------------------------------------
def auto_detect_interface():
    interfaces = get_if_list()
    for i in interfaces:
        if ("Wi-Fi" in i) or ("Wireless" in i) or ("Intel" in i):
            return i

    # Fallback to first interface
    return interfaces[0]


INTERFACE = auto_detect_interface()
print(f"\n======================================")
print(f"🚀 Packet Sniffer Started")
print(f"📡 Listening on: {INTERFACE}")
print(f"📘 Threat Intel Enabled: {THREAT_INTEL_ENABLED}")
print(f"======================================\n")

conf.use_pcap = True
conf.sniff_promisc = True


# -------------------------------------------------------------------
# 3. Main Packet Callback
# -------------------------------------------------------------------
def packet_callback(packet):
    try:
        if IP not in packet:
            return

        src = packet[IP].src
        dst = packet[IP].dst
        proto = str(packet[IP].proto)
        bytes_len = len(packet)
        now = timezone.now()  # timezone-aware timestamp

        # -------------------------------
        # 1. Log packet into DB
        # -------------------------------
        NetworkLog.objects.create(
            source_ip=src,
            destination_ip=dst,
            protocol=proto,
            bytes_transferred=bytes_len,
            timestamp=now,
        )

        print(f"[LOG] {src} → {dst}  | {bytes_len} bytes | proto {proto}")

        # -------------------------------
        # 2. Threat Intelligence
        # -------------------------------
        if THREAT_INTEL_ENABLED:
            if ThreatIP.objects.filter(ip=src).exists():
                print(f"⚠ Threat Intel Alert: Malicious Source {src}")
                Alert.objects.create(
                    message=f"Malicious source IP detected: {src}",
                    severity="High"
                )
            if ThreatIP.objects.filter(ip=dst).exists():
                print(f"⚠ Threat Intel Alert: Malicious Destination {dst}")
                Alert.objects.create(
                    message=f"Connection to malicious IP: {dst}",
                    severity="High"
                )

        # -------------------------------
        # 3. Run your anomaly detectors
        # -------------------------------
        detect_high_traffic()
        detect_port_scan()
        detect_icmp_flood()

    except Exception as e:
        print("❌ Callback error:", e)


# -------------------------------------------------------------------
# 4. Start sniffing
# -------------------------------------------------------------------
try:
    sniff(
        iface=INTERFACE,
        prn=packet_callback,
        store=False,
        filter="ip",
    )
except PermissionError:
    print("\n❌ ERROR: Need Administrator permissions to sniff.")
    print("➡ Run CMD or PowerShell as Administrator.\n")
except KeyboardInterrupt:
    print("\n🛑 Sniffer stopped by user.\n")
