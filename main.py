#!/usr/bin/env python3
"""
TP Wazuh – Automatisation et enrichissement des alertes
Point d'entrée principal

Usage:
  python3 main.py -i alerts_sample.json -w 60 -t 5
  python3 main.py -i alerts_sample.json --webhook https://webhook.site/votre-uuid
"""

import argparse
from parser import load_alerts, extract_fields
from aggregator import group_by_ip_and_period
from reporter import export_report
from notifier import notify_console, notify_webhook
from enrichment import enrich_summary

def main():
    ap = argparse.ArgumentParser(
        description="TP Wazuh – Parsing, agrégation et notification d'alertes"
    )
    ap.add_argument("-i", "--input", required=True, help="Fichier JSON d'alertes Wazuh")
    ap.add_argument("-w", "--window", type=int, default=60, help="Fenêtre temporelle en minutes (défaut: 60)")
    ap.add_argument("-t", "--threshold", type=int, default=5, help="Seuil de notification (défaut: 5)")
    ap.add_argument("--webhook", default=None, help="URL webhook de test (optionnel)")
    ap.add_argument("--dry-run", action="store_true", help="N'envoie pas le webhook, affiche seulement")
    args = ap.parse_args()

    # 1. Chargement
    raw = load_alerts(args.input)
    print(f"[+] {len(raw)} alertes chargées depuis {args.input}")

    # 2. Extraction
    parsed = [extract_fields(a) for a in raw]
    parsed = [p for p in parsed if p.get("src_ip")]
    print(f"[+] {len(parsed)} alertes avec adresse IP source")

    if not parsed:
        print("[!] Aucune alerte exploitable. Vérifiez le fichier d'entrée.")
        return

    # 3. Agrégation
    summary = group_by_ip_and_period(parsed, window_minutes=args.window)
    print(f"[+] {len(summary)} groupes (IP × période de {args.window} min)")

    # 4. Enrichissement
    summary = enrich_summary(summary)
    print("[+] Enrichissement des IP terminé")

    # 5. Rapport
    json_path, csv_path = export_report(summary)
    print(f"[+] Rapport JSON → {json_path}")
    print(f"[+] Rapport CSV  → {csv_path}")

    # 6. Notification
    notify_console(summary, threshold=args.threshold)

    if args.webhook and not args.dry_run:
        notify_webhook(summary, args.webhook, threshold=args.threshold)
    elif args.webhook and args.dry_run:
        print(f"[DRY-RUN] Webhook non envoyé (URL: {args.webhook})")


if __name__ == "__main__":
    main()
