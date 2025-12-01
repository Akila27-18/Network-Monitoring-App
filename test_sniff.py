from scapy.all import sniff, conf
conf.use_pcap = True
print("Sniffing with NPCAP...")
pkt = sniff(count=1)
print("Got packet:", pkt)

