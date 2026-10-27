"""Moteur d'analyse : statistiques en temps réel + détecteurs de comportements suspects."""
import threading
import time
from collections import Counter, defaultdict, deque

WINDOW = 10                    # secondes
SCAN_PORTS = 20                # destinations/ports distincts sondés par une même source dans la fenêtre
DNS_BURST = 100                # requêtes DNS d'une même source dans la fenêtre
DNS_LABEL_MAX = 40             # longueur max d'un label DNS "normal"
VOLUME_MAX = 50 * 1024 * 1024  # octets par source dans la fenêtre
COOLDOWN = 60                  # secondes entre deux alertes identiques


class Analyzer:
    def __init__(self):
        self._lock = threading.Lock()
        self.packets = deque(maxlen=500)
        self.alerts = deque(maxlen=200)
        self.proto = Counter()
        self.talkers = Counter()
        self.total_packets = 0
        self.total_bytes = 0
        self._next_id = 1
        self._recent = deque()
        self._syn = defaultdict(lambda: deque(maxlen=2000))
        self._dns = defaultdict(deque)
        self._vol = defaultdict(deque)
        self._vol_sum = defaultdict(int)
        self._arp = {}
        self._cool = {}

    # ---------- entrée ----------
    def ingest(self, p):
        now = p["ts"]
        with self._lock:
            self.total_packets += 1
            self.total_bytes += p["size"]
            self.proto[p["proto"]] += 1
            self.talkers[p["src"]] += p["size"]
            if len(self.talkers) > 5000:
                self.talkers = Counter(dict(self.talkers.most_common(1000)))
            self._recent.append(now)
            self.packets.append(p)
            self._detect(p, now)

    # ---------- détecteurs ----------
    def _detect(self, p, now):
        src = p["src"]

        if p["proto"] == "TCP" and p["flags"] == "S":
            q = self._syn[src]
            q.append((now, p["dst"], p["dport"]))
            self._purge(q, now)
            n = len({(d, port) for _, d, port in q})
            if n >= SCAN_PORTS:
                self._alert(("scan", src), "high", "Scan de ports probable",
                            f"{src} a envoyé des SYN vers {n} destinations/ports différents en {WINDOW} s.", now)

        if p["proto"] == "ARP" and p["info"] == "is-at" and p.get("mac"):
            old = self._arp.get(src)
            if old and old != p["mac"]:
                self._alert(("arp", src), "high", "Changement d'adresse MAC (ARP spoofing ?)",
                            f"L'adresse IP {src} est passée de {old} à {p['mac']}.", now)
            self._arp[src] = p["mac"]

        if p["proto"] == "DNS" and p["info"]:
            name = p["info"]
            longest = max((len(label) for label in name.split(".")), default=0)
            if longest > DNS_LABEL_MAX or len(name) > 100:
                self._alert(("dnslen", src, name[:30]), "medium", "Nom DNS inhabituel (tunneling ?)",
                            f"{src} interroge un nom de {len(name)} caractères : {name[:80]}", now)
            q = self._dns[src]
            q.append((now,))
            self._purge(q, now)
            if len(q) >= DNS_BURST:
                self._alert(("dnsburst", src), "medium", "Rafale de requêtes DNS",
                            f"{src} a envoyé {len(q)} requêtes DNS en {WINDOW} s.", now)

        q = self._vol[src]
        q.append((now, p["size"]))
        self._vol_sum[src] += p["size"]
        while q and now - q[0][0] > WINDOW:
            self._vol_sum[src] -= q.popleft()[1]
        if self._vol_sum[src] > VOLUME_MAX:
            self._alert(("vol", src), "medium", "Volume de trafic très élevé",
                        f"{src} a émis {self._vol_sum[src] // (1024 * 1024)} Mo en {WINDOW} s.", now)

    @staticmethod
    def _purge(q, now):
        while q and now - q[0][0] > WINDOW:
            q.popleft()

    def _alert(self, key, severity, title, detail, now):
        last = self._cool.get(key)
        if last is not None and now - last < COOLDOWN:
            return
        self._cool[key] = now
        self.alerts.appendleft({"id": self._next_id, "ts": now, "severity": severity,
                                "title": title, "detail": detail})
        self._next_id += 1

    # ---------- lecture ----------
    def stats(self):
        now = time.time()
        with self._lock:
            while self._recent and now - self._recent[0] > 5:
                self._recent.popleft()
            return {
                "pps": round(len(self._recent) / 5, 1),
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "protocols": dict(self.proto.most_common(8)),
                "talkers": self.talkers.most_common(8),
                "alerts": len(self.alerts),
            }

    def get_packets(self, n=40):
        with self._lock:
            return list(self.packets)[-n:][::-1]

    def get_alerts(self):
        with self._lock:
            return list(self.alerts)

    def get_alert(self, alert_id):
        with self._lock:
            return next((a for a in self.alerts if a["id"] == alert_id), None)
