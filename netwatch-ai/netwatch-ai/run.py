"""Point d'entrée : python run.py --demo   ou   sudo python run.py"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from netwatch.analyzer import Analyzer  # noqa: E402
from netwatch.capture import DemoCapture, LiveCapture  # noqa: E402
from netwatch.server import create_app  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="NetWatch AI, moniteur réseau temps réel")
    ap.add_argument("--demo", action="store_true", help="trafic simulé (pas besoin de droits admin)")
    ap.add_argument("--iface", help="interface réseau (ex: eth0, Wi-Fi)")
    ap.add_argument("--filter", help="filtre BPF (ex: 'tcp port 443')")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()

    analyzer = Analyzer()
    source = DemoCapture(analyzer.ingest) if args.demo else LiveCapture(analyzer.ingest, args.iface, args.filter)
    source.start()
    print(f"NetWatch AI lancé : http://127.0.0.1:{args.port}  ({'démo' if args.demo else 'capture réelle'})")
    try:
        create_app(analyzer).run(host="127.0.0.1", port=args.port, threaded=True)
    finally:
        source.stop()


if __name__ == "__main__":
    main()
