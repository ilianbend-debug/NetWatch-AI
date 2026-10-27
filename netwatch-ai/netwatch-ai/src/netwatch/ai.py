"""Connexion aux IA. Seuls un résumé de l'alerte et des stats globales sont envoyés, jamais le contenu des paquets.

Choix du fournisseur avec la variable NETWATCH_AI :
  - anthropic (défaut) : clé dans ANTHROPIC_API_KEY
  - ollama : IA locale sur ton PC, rien ne sort de ta machine
Modèle : variable NETWATCH_MODEL (optionnelle).
"""
import json
import os
import urllib.request

SYSTEM = (
    "Tu es un analyste réseau défensif. On te donne une alerte détectée sur le réseau de l'utilisateur "
    "(son propre PC ou réseau domestique) et quelques statistiques. Réponds en français, de façon claire "
    "pour un débutant : 1) ce que ça signifie, 2) si c'est probablement grave ou un faux positif, "
    "3) trois actions concrètes à faire. Maximum 150 mots."
)


def _prompt(alert, stats):
    return (
        f"Alerte ({alert['severity']}) : {alert['title']}\n"
        f"Détail : {alert['detail']}\n\n"
        f"Protocoles vus : {stats['protocols']}\n"
        f"Plus gros émetteurs (octets) : {stats['talkers'][:5]}"
    )


def explain(alert, stats):
    provider = os.getenv("NETWATCH_AI", "anthropic").lower()
    prompt = _prompt(alert, stats)
    try:
        if provider == "ollama":
            return _ollama(prompt)
        return _anthropic(prompt)
    except Exception as e:  # noqa: BLE001
        return f"IA indisponible : {e}"


def _anthropic(prompt):
    import anthropic

    client = anthropic.Anthropic()  # lit ANTHROPIC_API_KEY
    msg = client.messages.create(
        model=os.getenv("NETWATCH_MODEL", "claude-sonnet-5-5"),
        max_tokens=500,
        system=SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text


def _ollama(prompt):
    body = json.dumps({
        "model": os.getenv("NETWATCH_MODEL", "llama3.1"),
        "stream": False,
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request("http://127.0.0.1:11434/api/chat", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)["message"]["content"]
