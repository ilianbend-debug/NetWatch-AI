# NetWatch AI

Un moniteur réseau temps réel, façon Wireshark, avec une IA qui t'explique ce qui se passe.
Il surveille **ton propre PC et ton propre réseau** : trafic en direct, détection de comportements suspects, explication des alertes en français.

## Ce que ça fait

- Capture des paquets en direct (TCP, UDP, DNS, ARP, ICMP)
- Dashboard web local avec courbe de trafic, paquets, protocoles et plus gros émetteurs
- Détecteurs intégrés : scan de ports, ARP spoofing, DNS suspect (tunneling), rafale DNS, volume anormal
- Bouton "Expliquer avec l'IA" sur chaque alerte (Claude, ou une IA locale avec Ollama)

## Lancer en 2 minutes

```bash
pip install -r requirements.txt
python run.py --demo
```

Ouvre ensuite http://127.0.0.1:5000. Le mode démo simule du trafic et de fausses attaques : aucun droit spécial nécessaire.

## Capture réelle

- Windows : installe [Npcap](https://npcap.com), puis lance le terminal en administrateur
- Linux / macOS : `sudo python run.py`

Options : `--iface eth0`, `--filter "tcp port 443"`, `--port 8080`.

## Brancher une IA

```bash
# Claude (par défaut)
export ANTHROPIC_API_KEY="ta-clé"

# Ou une IA 100 % locale avec Ollama : rien ne quitte ton PC
export NETWATCH_AI=ollama
export NETWATCH_MODEL=llama3.1
```

L'IA reçoit uniquement le résumé de l'alerte et des statistiques globales. Le contenu des paquets n'est jamais conservé ni envoyé.

## Règles d'usage

Surveille uniquement des machines et des réseaux qui t'appartiennent, ou pour lesquels tu as une autorisation. Le dashboard n'écoute que sur 127.0.0.1.

## Tests

```bash
pip install pytest
pytest
```

## Idées pour la suite

- [ ] Associer chaque connexion au programme qui l'ouvre (psutil)
- [ ] Géolocalisation des IP
- [ ] Export des alertes et des paquets (.pcap)
- [ ] Plusieurs IA en parallèle pour recouper les analyses
- [ ] Règles de détection personnalisables
