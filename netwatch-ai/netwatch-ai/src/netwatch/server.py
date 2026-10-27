"""Serveur web local du dashboard (accessible uniquement depuis ton PC)."""
from flask import Flask, jsonify, send_from_directory

from . import ai


def create_app(analyzer):
    app = Flask(__name__, static_folder="static")

    @app.get("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.get("/api/stats")
    def stats():
        return jsonify(analyzer.stats())

    @app.get("/api/packets")
    def packets():
        return jsonify(analyzer.get_packets())

    @app.get("/api/alerts")
    def alerts():
        return jsonify(analyzer.get_alerts())

    @app.post("/api/explain/<int:alert_id>")
    def explain(alert_id):
        alert = analyzer.get_alert(alert_id)
        if alert is None:
            return jsonify({"text": "Alerte introuvable."}), 404
        return jsonify({"text": ai.explain(alert, analyzer.stats())})

    return app
