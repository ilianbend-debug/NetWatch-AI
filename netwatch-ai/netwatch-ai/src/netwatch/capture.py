"""Sources de paquets : capture réelle (scapy) ou mode démo (trafic simulé)."""
import random
import threading
import time


def make_packet(proto, src, dst, sport=None, dport=None, size=60, flags="", info="", mac=None, ts=None):
    return {
        "ts": ts if ts is not None else time.time(),
        "proto": proto,
        "src": src,
        "dst": dst,
        "sport": sport,
        "dport": dport,
        "size": size,
        "flags": flags,
        "info": info,
        "mac": mac,
    }


def parse_packet(pkt):
    """Transforme un paquet scapy en dictionnaire simple. Le contenu (payload) n'est jamais conservé."""
    from scapy.all import ARP, DNS, DNSQR, ICMP, IP, IPv6, TCP, UDP

    p = make_packet("OTHER", "?", "?", size=len(pkt))
    if pkt.haslayer(ARP):
        a = pkt[ARP]
        p.update(proto="ARP", src=a.psrc, dst=a.pdst, mac=a.hwsrc, info="who-has" if a.op == 1 else "is-at")
        return p
    if pkt.haslayer(IP):
        p["src"], p["dst"] = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        p["src"], p["dst"] = pkt[IPv6].src, pkt[IPv6].dst
    else:
        return p
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        p.update(proto="TCP", sport=t.sport, dport=t.dport, flags=str(t.flags))
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        p.update(proto="UDP", sport=u.sport, dport=u.dport)
    elif pkt.haslayer(ICMP):
        p["proto"] = "ICMP"
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
        p["proto"] = "DNS"
        p["info"] = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
    return p


class LiveCapture:
    """Capture réelle. Demande les droits administrateur (et Npcap sous Windows)."""

    def __init__(self, on_packet, iface=None, bpf=None):
        self.on_packet = on_packet
        self.iface = iface
        self.bpf = bpf
        self._sniffer = None

    def start(self):
        from scapy.all import AsyncSniffer

        self._sniffer = AsyncSniffer(
            iface=self.iface,
            filter=self.bpf,
            prn=lambda pkt: self.on_packet(parse_packet(pkt)),
            store=False,
        )
        self._sniffer.start()

    def stop(self):
        if self._sniffer is not None and self._sniffer.running:
            self._sniffer.stop()


class DemoCapture:
    """Trafic simulé pour tester sans droits admin ni scapy. Déclenche de fausses attaques."""

    def __init__(self, on_packet):
        self.on_packet = on_packet
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        rnd = random.Random()
        me = "192.168.1.20"
        hosts = ["142.250.74.206", "151.101.1.69", "104.18.32.7", "93.184.216.34", "192.168.1.1"]
        names = ["www.google.com", "api.github.com", "fonts.gstatic.com", "cdn.jsdelivr.net"]
        last_event = time.time() - 37  # première fausse alerte après ~8 s
        while not self._stop.is_set():
            r = rnd.random()
            host = rnd.choice(hosts)
            if r < 0.55:
                self.on_packet(make_packet("TCP", me, host, rnd.randint(40000, 60000), 443, rnd.randint(60, 1400), "PA"))
            elif r < 0.8:
                self.on_packet(make_packet("TCP", host, me, 443, rnd.randint(40000, 60000), rnd.randint(60, 1500), "A"))
            elif r < 0.93:
                self.on_packet(make_packet("DNS", me, "192.168.1.1", 53000, 53, 80, info=rnd.choice(names)))
            else:
                self.on_packet(make_packet("UDP", me, host, 50000, 443, rnd.randint(100, 1200)))
            if time.time() - last_event > 45:
                self._fake_attacks(me)
                last_event = time.time()
            time.sleep(rnd.uniform(0.01, 0.12))

    def _fake_attacks(self, me):
        attacker = "192.168.1.66"
        for port in range(1, 31):
            self.on_packet(make_packet("TCP", attacker, me, 40000, port, 60, "S"))
        weird = "x8f3k29dj39dk39dkd93kdj39dk39dkd93kd93kdj39dk39dkd9.demo.example"
        self.on_packet(make_packet("DNS", me, "192.168.1.1", 53000, 53, 120, info=weird))
