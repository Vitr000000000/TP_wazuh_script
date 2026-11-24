"""
Notifications console et webhook.
"""

from typing import Any

import requests


def notify_console(summary: list[dict[str, Any]], threshold: int = 5) -> None:
    """Affiche les IP dont le nombre d'événements dépasse le seuil."""
    critical = [s for s in summary if s.get("count", 0) >= threshold]

    if not critical:
        print(f"\n[INFO] Aucune IP au-dessus du seuil ({threshold}).")
        return

    print(f"\n=== {len(critical)} IP(s) suspecte(s) – seuil ≥ {threshold} ===")
    print(f"{'IP source':<20} {'Count':>6}  {'Sev max':>7}  Hôtes")
    print("-" * 70)
    for item in critical:
        hosts = ", ".join(item.get("hosts") or []) or "-"
        print(
            f"{item.get('src_ip', '?'):<20} "
            f"{item.get('count', 0):>6}  "
            f"{item.get('max_severity', 0):>7}  "
            f"{hosts}"
        )
    print()


def notify_webhook(
    summary: list[dict[str, Any]],
    webhook_url: str,
    threshold: int = 5,
) -> None:
    """
    Envoie un POST JSON vers l'URL de test (webhook.site, RequestBin, Slack, etc.).
    """
    critical = [s for s in summary if s.get("count", 0) >= threshold]
    if not critical:
        print("[INFO] Rien à envoyer au webhook.")
        return

    payload = {
        "source": "tp-wazuh-automatisation",
        "threshold": threshold,
        "count_ips": len(critical),
        "ips": [
            {
                "ip": i.get("src_ip"),
                "count": i.get("count"),
                "max_severity": i.get("max_severity"),
                "hosts": i.get("hosts"),
                "rules": i.get("rules"),
                "period": i.get("period"),
            }
            for i in critical[:25]  # limite de sécurité
        ],
    }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=12)
        resp.raise_for_status()
        print(f"[OK] Webhook envoyé → status {resp.status_code}")
    except requests.RequestException as exc:
        print(f"[ERREUR] Échec envoi webhook : {exc}")
