import os
import django
import traceback
import time
from django.utils import timezone
from scapy.all import sniff, get_if_list, conf, IP, ICMP

# ------------------ 1. Django setup ------------------
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "network_monitor.settings")
django.setup()

from monitor.models import NetworkLog, Alert

# Optional ThreatIntel
try:
    from threatintel.models import ThreatIP
    THREAT_INTEL_ENABLED = True
except Exception:
    THREAT_INTEL_ENABLED = False

# ------------------ 2. Auto-detect interface ------------------
def choose_interface():
    interfaces = get_if_list()
    for iface in interfaces:
        if ("Wi-Fi" in iface) or ("Wireless" in iface) or ("Ethernet" in iface) or ("Intel" in iface):
            return iface
    return interfaces[0]  # fallback to first interface

INTERFACE = "\\Device\\NPF_{7BEE7DF4-F0AC-4A00-8426-F29888BA0183}"

print(f"Sniffing on interface: {INTERFACE}")
print(f"Threat Intelligence Enabled: {THREAT_INTEL_ENABLED}\n")

conf.use_pcap = True
conf.sniff_promisc = True

# ------------------ 3. Packet callback ------------------
def packet_callback(pkt):
    try:
        if IP not in pkt:
            return

        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = str(pkt[IP].proto)
        length = len(pkt)
        now = timezone.now()

        # Print ICMP packets for clarity
        if ICMP in pkt:
            print(f"ICMP Packet: {src} -> {dst} | {length} bytes")

        # Log packet to DB
        try:
            NetworkLog.objects.create(
                source_ip=src,
                destination_ip=dst,
                protocol=proto,
                bytes_transferred=length,
                timestamp=now
            )
            print(f"[LOG] {src} → {dst} | {length} bytes | proto {proto}")
        except Exception as e:
            print("❌ Failed to log packet:", e)
            traceback.print_exc()

        # Threat Intelligence
        if THREAT_INTEL_ENABLED:
            if ThreatIP.objects.filter(ip=src).exists():
                print(f"⚠ Threat: Malicious Source {src}")
                Alert.objects.create(
                    message=f"Malicious source IP detected: {src}",
                    severity="High"
                )
            if ThreatIP.objects.filter(ip=dst).exists():
                print(f"⚠ Threat: Malicious Destination {dst}")
                Alert.objects.create(
                    message=f"Connection to malicious IP: {dst}",
                    severity="High"
                )

        # Placeholder for future anomaly detection
        # detect_high_traffic()
        # detect_port_scan()
        # detect_icmp_flood()

    except Exception as e:
        print("❌ Callback error:", e)
        traceback.print_exc()

# ------------------ 4. Continuous sniffing ------------------
while True:
    try:
        sniff(iface=INTERFACE, prn=packet_callback, store=False, filter="ip")
    except PermissionError:
        print("❌ Permission denied. Run the script as Administrator/root.")
        break
    except KeyboardInterrupt:
        print("\n🛑 Sniffer stopped by user.")
        break
    except Exception as e:
        print("⚠ Sniffer error:", e)
        traceback.print_exc()
        print("⏳ Restarting sniffing in 5 seconds...")
        time.sleep(5)