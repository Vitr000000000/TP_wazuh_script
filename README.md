# TP Wazuh – Automatisation et enrichissement des alertes

Script de démonstration aligné sur le cours « Automatisation et enrichissement des alertes ».

## Contenu

| Fichier            | Rôle                                      |
|--------------------|-------------------------------------------|
| `main.py`          | Point d'entrée (CLI)                      |
| `parser.py`        | Chargement JSON / NDJSON + extraction     |
| `aggregator.py`    | Regroupement par IP + fenêtre temporelle  |
| `reporter.py`      | Export CSV + JSON                         |
| `notifier.py`      | Notification console + webhook            |
| `alerts_sample.json` | Jeu de données de test (14 alertes)     |

## Installation rapide

```bash
cd tp_wazuh_starter
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Exécution avec les données de test

```bash
python3 main.py -i alerts_sample.json -w 60 -t 5
```

Vous devriez voir :
- 14 alertes chargées
- plusieurs groupes IP/période
- un rapport JSON + CSV dans le dossier `reports/`
- un résumé console des IP au-dessus du seuil

## Avec webhook de test

1. Ouvrez https://webhook.site et copiez l’URL unique
2. Lancez :

```bash
python3 main.py -i alerts_sample.json -t 5 \
  --webhook https://webhook.site/votre-uuid-ici
```

## Utiliser de vraies alertes Wazuh

Sur le manager :

```bash
# Copier un extrait récent (adapter le chemin selon votre version)
sudo tail -n 200 /var/ossec/logs/alerts/alerts.json > ~/alerts_live.json
# ou extraire seulement les règles SSH
sudo grep -E '"id":"571[0-2]"' /var/ossec/logs/alerts/alerts.json | tail -100 > ~/alerts_ssh.json
```

Puis :

```bash
python3 main.py -i ~/alerts_ssh.json -w 30 -t 3
```

## Options CLI

```
-i / --input      Fichier d'alertes (obligatoire)
-w / --window     Fenêtre d'agrégation en minutes (défaut 60)
-t / --threshold  Seuil de notification (défaut 5)
--webhook         URL de notification
--dry-run         N'envoie pas le webhook
```

## Prochaines étapes (bonus du TP)

- Ajouter un enrichissement mock ou réel (AbuseIPDB)
- Gérer un cache local des scores de réputation
- Brancher le script en Active Response Wazuh
- Ajouter des tests unitaires (pytest)

## Rappels de sécurité

- Ne committez jamais de clés API
- Toute action de containment automatique doit rester sous validation humaine en production
- Respectez les rate limits des services externes
